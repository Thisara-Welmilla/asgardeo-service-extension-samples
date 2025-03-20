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

    public function init() {
        io:print("Custom authentication action e2e service started.");
    }

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
            string redirectUrl = string `${HOST_URL}/api/pin_entry?flowId=${flowId}`;

            json payload = { actionStatus: "INCOMPLETE", operations: [{ op: "redirect", url: redirectUrl }] };
            http:Response response = new;
            response.statusCode = 200;
            response.setPayload(payload);
            
            io:println(response);
            check caller->respond(response);
        }
    }

    // PIN Entry Page
    resource function get pin_entry(http:Caller caller, http:Request req) returns error? {

        var queryParams = req.getQueryParams();
        string flowId = queryParams.get("flowId")[0];

        if (!sessionStore.hasKey(flowId)) {
            http:Response response = new;
            response.statusCode = 400;
            response.setPayload("Invalid or expired Flow ID.");
            check caller->respond(response);
        } else {
            json session = sessionStore.get(flowId);
            string userField;
            string tenant = check session.tenant;
            if (AUTH_MODE == "second_factor" && sessionStore.hasKey("user")) {
                string userId = check session.user.id;
                userField = string `<input type="hidden" name="userId" value="${userId}" />`;
            } else {
                userField = string `<input type="text" name="username" required placeholder="Username" />`;
            }
            string htmlContent = string `
                    <html>
    <body>
        <h2>Enter Your PIN</h2>
        <form id="pinForm">
            <input type="hidden" id="flowId" value="${flowId}" />
            <input type="hidden" id="tenant" value="${tenant}" />
            ${userField}
            <input type="password" id="pin" required placeholder="PIN"/>
            <button type="submit">Submit</button>
        </form>

        <script>
            document.getElementById("pinForm").addEventListener("submit", function(event) {
                event.preventDefault(); // Prevent default form submission
                
                const payload = {
                    flowId: document.getElementById("flowId").value,
                    tenant: document.getElementById("tenant").value,
                    pin: document.getElementById("pin").value
                };

                fetch("/api/validate_pin", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify(payload)
                })
                .then(response => response.json())
                .then(data => console.log("Success:", data))
                .catch(error => console.error("Error:", error));
            });
        </script>
    </body>
</html>`;
            http:Response response = new;
            response.setPayload(htmlContent);
            response.setHeader("Content-Type", "text/html");
            response.statusCode = 200;
            check caller->respond(response);
        }
    }

    resource function post validate_pin(http:Caller caller, http:Request req) returns error? {

        json requestJson = check req.getJsonPayload();
        string flowId = check requestJson.flowId.ensureType();
        string pin = check requestJson.pin.ensureType();
        string tenantDomain = check requestJson.tenant.ensureType();

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
        string redirectUrl = string `${BASE_WSO2_IAM_PROVIDER_URL}/t/${tenantDomain}/commonauth?flowId=${flowId}`;
        http:Response res = new;
        res.statusCode = 302;
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
