import ballerina/http;
import ballerina/io;
import ballerina/log;
import ballerina/config;
import ballerina/json;

listener http:Listener appListener = new(3000);

map<json> sessionStore = {};

string AUTH_MODE = config:getAsString("AUTH_MODE", "federated");
string BASE_WSO2_IAM_PROVIDER_URL = config:getAsString("BASE_WSO2_IAM_PROVIDER_URL", "https://localhost:9443");
string HOST_URL = config:getAsString("HOST_URL", "http://localhost:3000");

json userConfig = {};

function init() returns error? {
    string? userConfigStr = config:getAsString("USER_CONFIG");
    if (userConfigStr != null) {
        userConfig = checkpanic json:fromString(userConfigStr);
    } else {
        string usersFilePath = "../data/users.json";
        json fileContents = checkpanic fileutils:readFileAsString(usersFilePath);
        userConfig = checkpanic json:fromString(fileContents);
        io:println("Loaded users from local file");
    }
}

// Get user database based on the current auth mode
function getUserDatabase() returns json[] {
    json[] federated = <json[]>userConfig["federated"];
    json[] internal = <json[]>userConfig["internal"];
    if (AUTH_MODE == "federated") {
        return federated;
    } else if (AUTH_MODE == "internal") {
        return internal;
    }
    return federated.concat(internal);
}

// Utility function for structured error handling
function handleError(http:Caller caller, int status, string errorMessage, string errorDescription) returns error? {
    json response = { "actionStatus": "ERROR", "errorMessage": errorMessage, "errorDescription": errorDescription };
    checkpanic caller->respond(response, status);
}

// Log requests and responses
function logRequest(http:Caller caller, http:CallerRequest request) {
    log:printInfo("Request Received", {"method": request.method.toString(), "url": request.url.toString(), "headers": request.headers, "body": request.body});
}

function logResponse(http:Caller caller, json resBody) {
    log:printInfo("Response Sent", {"url": caller.getRequest().url.toString(), "responseBody": resBody});
}

// Health Check Endpoint
service /api on listener appListener {

    resource function get health(http:Caller caller) returns error? {
        logRequest(caller, caller.getRequest());
        json response = { "status": "ok", "message": "Service is running." };
        logResponse(caller, response);
        checkpanic caller->respond(response);
    }

    // Authentication Request
    resource function post authenticate(http:Caller caller, json body) returns error? {
        logRequest(caller, caller.getRequest());
        string flowId = check body["flowId"].toString();
        json event = <json>body["event"];

        if (flowId == "") {
            return handleError(caller, 400, "missingFlowId", "Flow ID is required.");
        }

        if (!sessionStore.hasKey(flowId)) {
            sessionStore[flowId] = {
                "tenant": event["tenant"]["name"],
                "organization": event["organization"] ? event["organization"]["id"] : null,
                "user": (AUTH_MODE == "second_factor") ? event["user"] : null
            };
            string pinEntryUrl = HOST_URL + "/api/pin-entry?flowId=" + flowId;
            json response = { "actionStatus": "INCOMPLETE", "operations": [{ "op": "redirect", "url": pinEntryUrl }] };
            logResponse(caller, response);
            checkpanic caller->respond(response);
        } else {
            json session = <json>sessionStore[flowId];
            json response = (session["status"] == "SUCCESS") ?
                { "actionStatus": "SUCCESS", "data": { "user": session["user"] } } :
                { "actionStatus": "FAILED", "failureReason": "userNotFound", "failureDescription": "Unable to find user for given credentials." };
            logResponse(caller, response);
            checkpanic caller->respond(response);
        }
    }

    // Serve PIN Entry Page
    resource function get pinEntry(http:Caller caller, string flowId) returns error? {
        logRequest(caller, caller.getRequest());
        if (flowId == "" || !sessionStore.hasKey(flowId)) {
            checkpanic caller->respond("Invalid or expired Flow ID.", 400);

