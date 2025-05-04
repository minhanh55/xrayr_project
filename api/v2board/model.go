// Deprecated: after 2023.6.1
package v2board

type UserTraffic struct {
	UID      int   `json:"user_id"`
	Upload   int64 `json:"u"`
	Download int64 `json:"d"`
}
type OnlineUser struct {
	UID int    `json:"user_id"`
	IP  string `json:"ip"`
}