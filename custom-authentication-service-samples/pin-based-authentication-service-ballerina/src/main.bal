import ballerina/http;
import ballerina/io;

// Env configurations
configurable int SERVER_PORT = 3000;
configurable string AUTH_MODE = "federated";
configurable string BASE_WSO2_IAM_PROVIDER_URL = "https://localhost:9443";
configurable string HOST_URL = "http://localhost:3000";

// Define server listener
listener http:Listener authListener = new (SERVER_PORT);

// In-memory session store
map<json> sessionStore = {};

function getUserDatabase() returns User[] {

    User[] allUsers = [];
    string|error jsonString = io:fileReadString("user.json");
    if (jsonString is error) {
       return allUsers;
    }
    json|error parsedJson = jsonString.fromJsonString();
    if (parsedJson is error) {
       return allUsers;
    }

    if parsedJson is json[] {
            json[] parsedJsonList = parsedJson;

            foreach var item in parsedJsonList {
                User|error newUser = item.fromJsonWithType();
                if (newUser is User) {
                    allUsers.push(newUser);
                }
                
            }
    }
    
    return allUsers;
}

// Endpoints of the custom authentication service
service /api on authListener {

    // Health Check Endpoint
    resource function get health(http:Caller caller, http:Request req) returns error? {

        json response = { status: "ok", message: "Service is running." };
        check caller->respond(response);
    }

    // Authentication Endpoint
    resource function post authenticate(http:Caller caller, http:Request req) returns error? {

        json requestJson = check req.getJsonPayload();
        string flowId = check requestJson.flowId.ensureType();
        json event = check requestJson.event;

        if (sessionStore.hasKey(flowId)) {
            json session = sessionStore[flowId];

            json response = session.status == "SUCCESS"
                ? { actionStatus: "SUCCESS", data: { user: check session.user } }
                : { actionStatus: "FAILED", failureReason: "userNotFound" };

            check caller->respond(response);
        } else {
            sessionStore[flowId] = { tenant: check event.tenant.name };
            string redirectUrl = string `${HOST_URL}/api/pin-entry?flowId=${flowId}`;

            json response = { actionStatus: "INCOMPLETE", operations: [{ op: "redirect", url: redirectUrl }] };
            check caller->respond(response);
        }
    }

    // PIN Entry Page
    resource function get pinEntry(http:Caller caller, http:Request req) returns error? {

        var queryParams = req.getQueryParams();
        string[] flowIds = queryParams.get("flowId");
        string flowId = flowIds[0];

        if (!sessionStore.hasKey(flowId)) {
            http:Response response = new;
            response.statusCode = 400;
            response.setPayload("Invalid or expired Flow ID.");
            check caller->respond(response);
        } else {
            string htmlContent = string `
                <html>
                <body>
                    <h2>Enter Your PIN</h2>
                    <form action="/api/validate-pin" method="POST">
                        <input type="hidden" name="flowId" value="${flowId}" />
                        <input type="password" name="pin" required placeholder="PIN"/>
                        <button type="submit">Submit</button>
                    </form>
                </body>
                </html>
            `;
            http:Response response = new;
            response.setPayload(htmlContent);
            response.setHeader("Content-Type", "text/html");
            check caller->respond(response);
        }
    }

    resource function post validatePin(http:Caller caller, http:Request req) returns error? {

        json requestJson = check req.getJsonPayload();
        string flowId = check requestJson.flowId.ensureType();
        string pin = check requestJson.pin.ensureType();

        if (!sessionStore.hasKey(flowId)) {
            check caller->respond({ message: "Session correlating data not found.", status: 400 });
        }

        json session = sessionStore[flowId];
        User[] userDatabase = getUserDatabase();
        User[] matchingUser = [];

        // Filter users by pin
        foreach User user in userDatabase {
            if (user.pin == pin) {
                matchingUser.push(user);
            }
        }

        // Check if matching user exists
        if (matchingUser.length() > 0) {
            sessionStore[flowId] = { status: "SUCCESS", user: matchingUser.toJson() };
        } else {
            sessionStore[flowId] = { status: "FAILED" };
        }

        // Redirect to authorize endpoint with flowId to continue the login flow.
        string tenantDomain = check session.tenant;
        string redirectUrl = string `${BASE_WSO2_IAM_PROVIDER_URL}/t/${tenantDomain}/commonauth?flowId=${flowId}`;
        http:Response res = new;
        check caller->redirect(locations = [redirectUrl], code = 302, response = res);
    }
}

type Claim record { 
    string uri; 
    string value;
};

type UserData record { 
    string id; 
    Claim[] claims; 
};

type User record {
    string id;
    string username;
    string pin;
    UserData data;
};
