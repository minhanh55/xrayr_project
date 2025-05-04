package v2board

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bitly/go-simplejson"
	"github.com/go-resty/resty/v2"

	"github.com/qtai2901/new_xrayr/api"
)

// APIClient create an api client to the panel.
type APIClient struct {
	client           *resty.Client
	APIHost          string
	NodeID           int
	Key              string
	NodeType         string
	EnableVless      bool
	VlessFlow        string
	SpeedLimit       float64
	DeviceLimit      int
	DeviceOnline     int
	LocalRuleList    []api.DetectRule
	LastReportOnline map[int]int
	ConfigResp       *simplejson.Json
	access           sync.Mutex
}

// New create an api instance
func New(apiConfig *api.Config) *APIClient {

	client := resty.New()
	client.SetRetryCount(3)
	if apiConfig.Timeout > 0 {
		client.SetTimeout(time.Duration(apiConfig.Timeout) * time.Second)
	} else {
		client.SetTimeout(5 * time.Second)
	}
	client.OnError(func(req *resty.Request, err error) {
		if v, ok := err.(*resty.ResponseError); ok {
			// v.Response contains the last response from the server
			// v.Err contains the original error
			log.Print(v.Err)
		}
	})
	client.SetBaseURL(apiConfig.APIHost)
	// Create Key for each requests
	
	client.SetQueryParams(map[string]string{
		"node_id": strconv.Itoa(apiConfig.NodeID),
		"token":   apiConfig.Key,
	})
	// Read local rule list
	localRuleList := readLocalRuleList(apiConfig.RuleListPath)
	apiClient := &APIClient{
		client:        client,
		NodeID:        apiConfig.NodeID,
		Key:           apiConfig.Key,
		APIHost:       apiConfig.APIHost,
		NodeType:      apiConfig.NodeType,
		EnableVless:   apiConfig.EnableVless,
		VlessFlow:     apiConfig.VlessFlow,
		SpeedLimit:    apiConfig.SpeedLimit,
		DeviceLimit:   apiConfig.DeviceLimit,
		LocalRuleList: localRuleList,
	}
	return apiClient
}

// readLocalRuleList reads the local rule list file
func readLocalRuleList(path string) (LocalRuleList []api.DetectRule) {

	LocalRuleList = make([]api.DetectRule, 0)
	if path != "" {
		// open the file
		file, err := os.Open(path)

		// handle errors while opening
		if err != nil {
			log.Printf("Error when opening file: %s", err)
			return LocalRuleList
		}

		fileScanner := bufio.NewScanner(file)

		// read line by line
		for fileScanner.Scan() {
			LocalRuleList = append(LocalRuleList, api.DetectRule{
				ID:      -1,
				Pattern: regexp.MustCompile(fileScanner.Text()),
			})
		}
		// handle first encountered error while reading
		if err := fileScanner.Err(); err != nil {
			log.Fatalf("Error while reading file: %s", err)
			return
		}

		file.Close()
	}

	return LocalRuleList
}

// Describe return a description of the client
func (c *APIClient) Describe() api.ClientInfo {
	return api.ClientInfo{APIHost: c.APIHost, NodeID: c.NodeID, Key: c.Key, NodeType: c.NodeType}
}

// Debug set the client debug for client
func (c *APIClient) Debug() {
	c.client.SetDebug(true)
}

func (c *APIClient) assembleURL(path string) string {
	return c.APIHost + path
}

func (c *APIClient) parseResponse(res *resty.Response, path string, err error) (*simplejson.Json, error) {
	if err != nil {
		return nil, fmt.Errorf("request %s failed: %s", c.assembleURL(path), err)
	}

	if res.StatusCode() > 400 {
		body := res.Body()
		return nil, fmt.Errorf("request %s failed: %s, %s", c.assembleURL(path), string(body), err)
	}
	rtn, err := simplejson.NewJson(res.Body())
	if err != nil {
		return nil, fmt.Errorf("ret %s invalid", res.String())
	}
	return rtn, nil
}

// GetNodeInfo will pull NodeInfo Config from sspanel
func (c *APIClient) GetNodeInfo() (nodeInfo *api.NodeInfo, err error) {
	var path string
	switch c.NodeType {
	case "V2ray":
		path = "/api/v1/server/SkyhtV2ray/config"
	case "Trojan":
		path = "/api/v1/server/SkyhtTrojan/config"
	case "Shadowsocks":
		if nodeInfo, err = c.ParseSSNodeResponse(); err == nil {
			return nodeInfo, nil
		} else {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported Node type: %s", c.NodeType)
	}
	

	res, err := c.client.R().
		SetQueryParam("local_port", "1").
		ForceContentType("application/json").
		Get(path)

	response, err := c.parseResponse(res, path, err)
	c.access.Lock()
	defer c.access.Unlock()
	c.ConfigResp = response
	if err != nil {
		return nil, err
	}

	switch c.NodeType {
	case "V2ray":
		nodeInfo, err = c.ParseV2rayNodeResponse(response)
	case "Trojan":
		nodeInfo, err = c.ParseTrojanNodeResponse(response)
	case "Shadowsocks":
		nodeInfo, err = c.ParseSSNodeResponse()
	default:
		return nil, fmt.Errorf("unsupported Node type: %s", c.NodeType)
	}

	if err != nil {
		res, _ := response.MarshalJSON()
		return nil, fmt.Errorf("Parse node info failed: %s, \nError: %s", string(res), err)
	}

	return nodeInfo, nil
}

func (c *APIClient) GetUserList() (UserList *[]api.UserInfo, err error) {
	var path string
	switch c.NodeType {
	case "V2ray":
		path = "/api/v1/server/SkyhtV2ray/user"
	case "Trojan":
		path = "/api/v1/server/SkyhtTrojan/user"
	case "Shadowsocks":
		path = "/api/v1/server/SkyhtShadowsocks/user"
	default:
		return nil, fmt.Errorf("unsupported Node type: %s", c.NodeType)
	}
	res, err := c.client.R().
		ForceContentType("application/json").
		Get(path)

	response, err := c.parseResponse(res, path, err)
	if err != nil {
		return nil, err
	}
	// var deviceLimit, localDeviceLimit int = 0, 0
	numOfUsers := len(response.Get("data").MustArray())
	userList := make([]api.UserInfo, numOfUsers)
	for i := 0; i < numOfUsers; i++ {
		user := api.UserInfo{}
		user.UID = response.Get("data").GetIndex(i).Get("id").MustInt()
		// user.SpeedLimit = uint64(c.SpeedLimit * 1000000 / 8)
		if c.SpeedLimit > 0 {
			user.SpeedLimit = uint64(c.SpeedLimit * 1000000 / 8)
		} else {
			user.SpeedLimit = uint64(response.Get("data").GetIndex(i).Get("speed_limit").MustInt() * 1000000 / 8)
		}
		user.DeviceLimit = c.DeviceLimit
		
		// deviceLimit := 0
		// if c.DeviceLimit > 0 {
		// 	deviceLimit = c.DeviceLimit
		// } else {
		// 	deviceLimit = response.Get("data").GetIndex(i).Get("limit_device").MustInt()
		// }

		// // Kiểm tra xem số lượng thiết bị trực tuyến có vượt quá giới hạn không.
		// if deviceLimit > 0 && response.Get("data").GetIndex(i).Get("device_online").MustInt() <= deviceLimit {
		// 	// Nếu số lượng thiết bị trực tuyến không vượt quá giới hạn, tiếp tục với logic khác.
		// 	// Đoạn mã tiếp theo ở đây.
		// 	lastOnline := 0
		// 	if v, ok := c.LastReportOnline[response.Get("data").GetIndex(i).Get("id").MustInt()]; ok {
		// 		lastOnline = v
		// 	}

		// 	localDeviceLimit := deviceLimit - response.Get("data").GetIndex(i).Get("device_online").MustInt() + lastOnline
		// 	if localDeviceLimit > 0 {
		// 		deviceLimit = localDeviceLimit
		// 	} else if lastOnline > 0 {
		// 		deviceLimit = lastOnline
		// 	} else {
		// 		// Trong trường hợp không có thiết bị khả dụng hoặc có thông tin cuối cùng về trực tuyến.
		// 		// Bạn có thể đưa ra quyết định tiếp theo ở đây.
		// 	}
		// } else {
		// 	// Nếu số lượng thiết bị trực tuyến vượt quá giới hạn, bỏ qua thiết bị này.
		// 	continue
		// }

		// user.DeviceLimit = deviceLimit

		switch c.NodeType {
		case "Shadowsocks":
			user.Email = response.Get("data").GetIndex(i).Get("secret").MustString()
			user.Passwd = response.Get("data").GetIndex(i).Get("secret").MustString()
			user.Method = response.Get("data").GetIndex(i).Get("cipher").MustString()
			user.Port = uint32(response.Get("data").GetIndex(i).Get("port").MustUint64())
		case "Trojan":
			user.UUID = response.Get("data").GetIndex(i).Get("trojan_user").Get("password").MustString()
			user.Email = response.Get("data").GetIndex(i).Get("trojan_user").Get("password").MustString()
		case "V2ray":
			user.UUID = response.Get("data").GetIndex(i).Get("v2ray_user").Get("uuid").MustString()
			user.Email = response.Get("data").GetIndex(i).Get("v2ray_user").Get("email").MustString()
			user.AlterID = uint16(response.Get("data").GetIndex(i).Get("v2ray_user").Get("alter_id").MustUint64())
		}
		userList[i] = user
	}
	return &userList, nil
}

// ReportNodeOnlineUsers reports online user ip
func (c *APIClient) ReportNodeOnlineUsers(onlineUserList *[]api.OnlineUser) error {
	c.access.Lock()
	defer c.access.Unlock()

	reportOnline := make(map[int]int)
	data := make([]OnlineUser, len(*onlineUserList))
	for i, user := range *onlineUserList {
		data[i] = OnlineUser{UID: user.UID, IP: user.IP}
		if _, ok := reportOnline[user.UID]; ok {
			reportOnline[user.UID]++
		} else {
			reportOnline[user.UID] = 1
		}
	}
	c.LastReportOnline = reportOnline // Update LastReportOnline
	var path string
	switch c.NodeType {
	case "V2ray":
		path = "/api/v1/server/SkyhtV2ray/online"
	case "Trojan":
		path = "/api/v1/server/SkyhtTrojan/online"
	case "Shadowsocks":
		path = "/api/v1/server/SkyhtShadowsocks/online"
	default:
		return fmt.Errorf("unsupported Node type: %s", c.NodeType)
	}
	res, err := c.client.R().
		SetQueryParam("node_id", strconv.Itoa(c.NodeID)).
		SetBody(data).
		ForceContentType("application/json").
		Post(path)
	_, err = c.parseResponse(res, path, err)
	if err != nil {
		return err
	}

	return nil
}

// ReportUserTraffic reports the user traffic
func (c *APIClient) ReportUserTraffic(userTraffic *[]api.UserTraffic) error {
	var path string
	switch c.NodeType {
	case "V2ray":
		path = "/api/v1/server/SkyhtV2ray/submit"
	case "Trojan":
		path = "/api/v1/server/SkyhtTrojan/submit"
	case "Shadowsocks":
		path = "/api/v1/server/SkyhtShadowsocks/submit"
	}

	data := make([]UserTraffic, len(*userTraffic))
	for i, traffic := range *userTraffic {
		data[i] = UserTraffic{
			UID:      traffic.UID,
			Upload:   traffic.Upload,
			Download: traffic.Download}
	}

	res, err := c.client.R().
		SetQueryParam("node_id", strconv.Itoa(c.NodeID)).
		SetBody(data).
		ForceContentType("application/json").
		Post(path)
	_, err = c.parseResponse(res, path, err)
	if err != nil {
		return err
	}
	return nil
}

// GetNodeRule implements the API interface
func (c *APIClient) GetNodeRule() (*[]api.DetectRule, error) {
	ruleList := c.LocalRuleList
	if c.NodeType != "V2ray" {
		return &ruleList, nil
	}

	// V2board only support the rule for v2ray
	// fix: reuse config response
	c.access.Lock()
	defer c.access.Unlock()
	ruleListResponse := c.ConfigResp.Get("routing").Get("rules").GetIndex(1).Get("domain").MustStringArray()
	for i, rule := range ruleListResponse {
		rule = strings.TrimPrefix(rule, "regexp:")
		ruleListItem := api.DetectRule{
			ID:      i,
			Pattern: regexp.MustCompile(rule),
		}
		ruleList = append(ruleList, ruleListItem)
	}
	return &ruleList, nil
}

// ReportNodeStatus implements the API interface
func (c *APIClient) ReportNodeStatus(nodeStatus *api.NodeStatus) (err error) {
	return nil
}

// ReportIllegal implements the API interface
func (c *APIClient) ReportIllegal(detectResultList *[]api.DetectResult) error {
	return nil
}

// ParseTrojanNodeResponse parse the response for the given nodeinfor format
func (c *APIClient) ParseTrojanNodeResponse(nodeInfoResponse *simplejson.Json) (*api.NodeInfo, error) {
	port := uint32(nodeInfoResponse.Get("local_port").MustUint64())
	host := nodeInfoResponse.Get("ssl").Get("sni").MustString()

	// Create GeneralNodeInfo
	nodeinfo := &api.NodeInfo{
		NodeType:          c.NodeType,
		NodeID:            c.NodeID,
		Port:              port,
		TransportProtocol: "tcp",
		EnableTLS:         true,
		Host:              host,
	}
	return nodeinfo, nil
}

// ParseSSNodeResponse parse the response for the given nodeinfor format
func (c *APIClient) ParseSSNodeResponse() (*api.NodeInfo, error) {
	var port uint32
	var method string
	userInfo, err := c.GetUserList()
	if err != nil {
		return nil, err
	}
	if len(*userInfo) > 0 {
		port = (*userInfo)[0].Port
		method = (*userInfo)[0].Method
	} else {
		return nil, errors.New("the number of node users is 0")
	}

	// Create GeneralNodeInfo
	nodeInfo := &api.NodeInfo{
		NodeType:          c.NodeType,
		NodeID:            c.NodeID,
		Port:              port,
		TransportProtocol: "tcp",
		CypherMethod:      method,
	}

	return nodeInfo, nil
}

// ParseV2rayNodeResponse parse the response for the given nodeinfor format
func (c *APIClient) ParseV2rayNodeResponse(nodeInfoResponse *simplejson.Json) (*api.NodeInfo, error) {
	var path, host, serviceName string
	var header json.RawMessage
	var enableTLS bool
	var alterID uint16 = 0

	inboundInfo := simplejson.New()
	if tmpInboundInfo, ok := nodeInfoResponse.CheckGet("inbound"); ok {
		inboundInfo = tmpInboundInfo
		// Compatible with v2board 1.5.5-dev
	} else if tmpInboundInfo, ok := nodeInfoResponse.CheckGet("inbounds"); ok {
		tmpInboundInfo := tmpInboundInfo.MustArray()
		marshalByte, _ := json.Marshal(tmpInboundInfo[0].(map[string]interface{}))
		inboundInfo, _ = simplejson.NewJson(marshalByte)
	} else {
		return nil, fmt.Errorf("unable to find inbound(s) in the nodeInfo")
	}

	port := uint32(inboundInfo.Get("port").MustUint64())
	transportProtocol := inboundInfo.Get("streamSettings").Get("network").MustString()

	switch transportProtocol {
	case "ws":
		path = inboundInfo.Get("streamSettings").Get("wsSettings").Get("path").MustString()
		host = inboundInfo.Get("streamSettings").Get("wsSettings").Get("headers").Get("Host").MustString()
	case "grpc":
		if data, ok := inboundInfo.Get("streamSettings").Get("grpcSettings").CheckGet("serviceName"); ok {
			serviceName = data.MustString()
		}
	case "tcp":
		if data, ok := inboundInfo.Get("streamSettings").Get("tcpSettings").CheckGet("header"); ok {
			if httpHeader, err := data.MarshalJSON(); err != nil {
				return nil, err
			} else {
				header = httpHeader
			}
		}

	}
	if inboundInfo.Get("streamSettings").Get("security").MustString() == "tls" {
		enableTLS = true
	} else {
		enableTLS = false
	}

	// Create GeneralNodeInfo
	// AlterID will be updated after next sync
	nodeInfo := &api.NodeInfo{
		NodeType:          c.NodeType,
		NodeID:            c.NodeID,
		Port:              port,
		AlterID:           alterID,
		TransportProtocol: transportProtocol,
		EnableTLS:         enableTLS,
		Path:              path,
		Host:              host,
		EnableVless:       c.EnableVless,
		VlessFlow:         c.VlessFlow,
		ServiceName:       serviceName,
		Header:            header,
	}
	return nodeInfo, nil
}
