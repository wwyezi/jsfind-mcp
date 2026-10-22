// A router config plus the code each view loads on demand. The route crawler
// can only reach this file by rendering /user/list, which is the whole point.
var routes = [
  { path: "/user/list", name: "user-list", component: UserList },
  { path: "/user/:userId", name: "user-detail", component: UserDetail },
  { path: "/order/list", name: "order-list", component: OrderList },
  { path: "/sys/config", name: "sys-config", component: SysConfig }
];

// only reachable through the /user/list route
function UserList() {
  return http.post("/internal/user/audit/list", { page: 1, status: "all" });
}
function SysConfig() {
  return fetch("/sys/config/raw", { credentials: "include" });
}
