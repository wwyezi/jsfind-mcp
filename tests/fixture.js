var API_BASE = "https://api.example.com/api/v2";
const http = axios.create({ baseURL: API_BASE, timeout: 5000 });
const SECRET_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const AK = "AKIAIOSFODNN7EXAMPLE";
const db = "jdbc:mysql://10.0.12.7:3306/orders";
const idCard = "110101199003078515";
const mail = "ops.lead@corp.internal";

function loadUser(userId, token) {
  return http.get("/user/" + userId + "/detail", { params: { page: 1, size: 20 } });
}
function saveOrder(payload) {
  return http.post("/order/submit?channel=app", payload);
}
function updateConfig(o) {
  o.endpoint = "https://admin.example.com/sys/config";
  o.secret = "s3cr3t-value-here";
}
const form = new URLSearchParams();
form.append("username", "admin");
form.append("password", "P@ssw0rd123");
fetch("/auth/login", { method: "POST", body: form });

var xhr = new XMLHttpRequest();
xhr.open("DELETE", "/admin/user/" + 42, true);

const router = { routes: [ { path: "/user/:userId", name: "u" }, { path: "/order/list", name: "o" } ] };
$.ajax({ url: "/report/export", type: "post", data: { format: "xlsx" } });

// --- identity and OA clues the new rules look for -------------------------
var session = { loginName: "zhangsan", employeeNo: "E10293", realName: "张三" };
var oaPortal = "/weaver/";

// --- transports that are not HTTP requests --------------------------------
// None of these appear in a fetch()/axios call shape, so an extractor that
// only understands those never sees them.
var pushChannel = new WebSocket("wss://push.example.com/ws/notify");
var liveFeed = new EventSource("/api/v1/notify/stream");
var gqlClient = new ApolloClient({ uri: "/api/graphql" });
const GET_USER_DETAIL = gql`
  query GetUserDetail($id: ID!) {
    user(id: $id) {
      id
      username
      email
      isAdmin
      rawPassword
      internalToken
    }
  }
`;
var authedSocket = new WebSocket("wss://push.example.com/ws/notify?token=" + SECRET_TOKEN);
