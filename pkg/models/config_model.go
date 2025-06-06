package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// ToolConfig 工具配置主结构体
type ToolConfig struct {
	ID        primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Name      string             `json:"name" bson:"name"`             // 配置名称
	IsDefault bool               `json:"is_default" bson:"is_default"` // 是否为默认配置
	CreatedAt time.Time          `json:"created_at" bson:"created_at"`
	UpdatedAt time.Time          `json:"updated_at" bson:"updated_at"`

	// 各工具配置
	NmapConfig      NmapConfig      `json:"nmap_config" bson:"nmap_config"`
	FfufConfig      FfufConfig      `json:"ffuf_config" bson:"ffuf_config"`
	SubfinderConfig SubfinderConfig `json:"subfinder_config" bson:"subfinder_config"`
	HttpxConfig     HttpxConfig     `json:"httpx_config" bson:"httpx_config"`
	FscanConfig     FscanConfig     `json:"fscan_config" bson:"fscan_config"`
	AfrogConfig     AfrogConfig     `json:"afrog_config" bson:"afrog_config"`
	NucleiConfig    NucleiConfig    `json:"nuclei_config" bson:"nuclei_config"`
	GogoConfig      GogoConfig      `json:"gogo_config" bson:"gogo_config"`
}

// NmapConfig Nmap工具配置
type NmapConfig struct {
	Enabled     bool   `json:"enabled" bson:"enabled"`           // 是否启用
	Ports       string `json:"ports" bson:"ports"`               // 端口范围，如 "80,443,8080-8090"
	ScanTimeout int    `json:"scan_timeout" bson:"scan_timeout"` // 扫描超时时间(秒)
	Concurrency int    `json:"concurrency" bson:"concurrency"`   // 并发数
}

// FfufConfig Ffuf工具配置
type FfufConfig struct {
	Enabled       bool   `json:"enabled" bson:"enabled"`                 // 是否启用
	WordlistPath  string `json:"wordlist_path" bson:"wordlist_path"`     // 字典文件路径
	Extensions    string `json:"extensions" bson:"extensions"`           // 扩展名，如 "php,asp,aspx"
	Threads       int    `json:"threads" bson:"threads"`                 // 线程数
	MatchHttpCode string `json:"match_http_code" bson:"match_http_code"` // 匹配的HTTP状态码
}

// SubfinderConfig Subfinder工具配置
type SubfinderConfig struct {
	Enabled    bool   `json:"enabled" bson:"enabled"`         // 是否启用
	ConfigPath string `json:"config_path" bson:"config_path"` // 配置文件路径
	Threads    int    `json:"threads" bson:"threads"`         // 线程数
	Timeout    int    `json:"timeout" bson:"timeout"`         // 超时时间(秒)
}

// HttpxConfig HttpX工具配置 (虽然不做配置，但为了完整性仍定义结构体)
type HttpxConfig struct {
	Enabled bool `json:"enabled" bson:"enabled"` // 是否启用
	Threads int  `json:"threads" bson:"threads"` // 线程数
	Timeout int  `json:"timeout" bson:"timeout"` // 超时时间(秒)
}

// FscanConfig Fscan工具配置
type FscanConfig struct {
	Enabled    bool   `json:"enabled" bson:"enabled"`         // 是否启用
	Threads    int    `json:"threads" bson:"threads"`         // 线程数
	Timeout    int    `json:"timeout" bson:"timeout"`         // 超时时间(秒)
	Ports      string `json:"ports" bson:"ports"`             // 默认端口范围
	OutputPath string `json:"output_path" bson:"output_path"` // 输出文件路径
	ScanMode   string `json:"scan_mode" bson:"scan_mode"`     // 扫描模式：fast/normal/deep
	Proxy      string `json:"proxy" bson:"proxy"`             // 代理设置
}

// GogoConfig Gogo工具配置
type GogoConfig struct {
	Enabled       bool   `json:"enabled" bson:"enabled"`               // 是否启用
	Ports         string `json:"ports" bson:"ports"`                   // 扫描端口
	Timeout       int    `json:"timeout" bson:"timeout"`               // 超时时间(秒)
	Thread        int    `json:"thread" bson:"thread"`                 // 线程数
	Mode          string `json:"mode" bson:"mode"`                     // 扫描模式：s(smart)/ss(supersmart)/default
	EnableExploit bool   `json:"enable_exploit" bson:"enable_exploit"` // 启用漏洞扫描
	Verbose       bool   `json:"verbose" bson:"verbose"`               // 启用主动指纹识别
	OutputPath    string `json:"output_path" bson:"output_path"`       // 输出文件目录
}

// AfrogConfig Afrog工具配置 (虽然不做配置，但为了完整性仍定义结构体)
type AfrogConfig struct {
	Enabled bool `json:"enabled" bson:"enabled"` // 是否启用
	Threads int  `json:"threads" bson:"threads"` // 线程数
}

// NucleiConfig Nuclei工具配置 (虽然不做配置，但为了完整性仍定义结构体)
type NucleiConfig struct {
	Enabled bool `json:"enabled" bson:"enabled"` // 是否启用
	Threads int  `json:"threads" bson:"threads"` // 线程数
}

// BeforeCreate 创建前的钩子
func (t *ToolConfig) BeforeCreate() {
	now := time.Now()
	t.CreatedAt = now
	t.UpdatedAt = now
}

// BeforeUpdate 更新前的钩子
func (t *ToolConfig) BeforeUpdate() {
	t.UpdatedAt = time.Now()
}

// GetDefaultConfig 获取默认配置
func GetDefaultConfig() *ToolConfig {
	return &ToolConfig{
		Name:      "默认配置",
		IsDefault: true,
		NmapConfig: NmapConfig{
			Enabled:     true,
			Ports:       "21,22,23,25,53,80,110,111,135,139,143,443,445,465,587,993,995,1080,1433,1521,3306,3389,5432,5900,6379,8080,8443",
			ScanTimeout: 300,
			Concurrency: 100,
		},
		FfufConfig: FfufConfig{
			Enabled:       true,
			WordlistPath:  "/usr/share/wordlist/dicc.txt",
			Extensions:    "php,asp,aspx,jsp,html,js",
			Threads:       50,
			MatchHttpCode: "200,204,301,302,307,401,403",
		},
		SubfinderConfig: SubfinderConfig{
			Enabled:    true,
			ConfigPath: "/etc/subfinder/config.yaml",
			Threads:    10,
			Timeout:    60,
		},
		HttpxConfig: HttpxConfig{
			Enabled: true,
			Threads: 50,
			Timeout: 10,
		},
		FscanConfig: FscanConfig{
			Enabled:    true,
			Threads:    100,
			Timeout:    60,
			Ports:      "7,9,11,13,17,19,21,22,23,26,37,38,43,49,51,53,67,69,70,79,80,81,82,83,84,85,86,88,89,102,104,111,113,119,121,123,135,137,138,139,143,161,175,179,199,211,264,311,389,443,444,445,465,500,502,503,512,515,520,548,554,564,587,623,631,636,646,666,771,777,789,800,801,808,853,873,880,888,902,992,993,995,999,1000,1022,1023,1024,1025,1026,1027,1080,1099,1177,1194,1200,1201,1234,1241,1248,1260,1290,1311,1344,1400,1433,1443,1471,1494,1515,1521,1554,1588,1701,1720,1723,1741,1777,1863,1883,1900,1911,1935,1962,1967,1991,2000,2001,2002,2020,2022,2030,2031,2049,2052,2053,2077,2080,2082,2083,2086,2087,2095,2096,2121,2123,2152,2181,2222,2223,2252,2323,2332,2375,2376,2379,2401,2404,2424,2427,2443,2455,2480,2501,2601,2628,3000,3001,3002,3006,3128,3260,3283,3288,3299,3306,3307,3310,3333,3388,3389,3390,3443,3460,3541,3542,3689,3690,3749,3780,4000,4022,4040,4063,4064,4111,4343,4369,4430,4433,4443,4444,4500,4505,4567,4664,4712,4730,4782,4786,4840,4848,4880,4911,4949,5000,5001,5002,5004,5005,5006,5007,5009,5050,5060,5084,5222,5258,5269,5351,5353,5357,5400,5432,5443,5500,5554,5555,5556,5560,5577,5601,5631,5672,5678,5683,5800,5801,5900,5901,5902,5903,5938,5984,5985,5986,6000,6001,6002,6003,6005,6006,6050,6060,6068,6110,6363,6379,6443,6488,6560,6565,6581,6588,6590,6600,6664,6665,6666,6667,6668,6669,6699,6881,6998,7000,7001,7002,7003,7005,7006,7010,7014,7025,7070,7071,7077,7080,7170,7288,7306,7307,7312,7401,7443,7474,7493,7537,7547,7548,7634,7657,7777,7779,7788,7911,8000,8001,8002,8003,8004,8006,8008,8009,8010,8015,8020,8025,8030,8040,8060,8069,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8091,8092,8093,8094,8095,8096,8097,8098,8099,8111,8112,8118,8123,8125,8126,8139,8159,8161,8180,8181,8182,8200,8222,8291,8333,8334,8377,8378,8388,8443,8500,8545,8546,8554,8649,8686,8800,8834,8880,8883,8887,8888,8889,8899,8983,8999,9000,9001,9002,9003,9009,9010,9030,9042,9050,9051,9080,9083,9090,9091,9100,9151,9191,9200,9295,9333,9418,9443,9444,9527,9530,9595,9600,9653,9700,9711,9869,9944,9981,9997,9999,10000,10001,10003,10162,10243,10333,10443,10554,11001,11211,11300,11310,12300,12345,13579,14000,14147,14265,16010,16030,16992,16993,17000,18000,18001,18080,18081,18245,18246,19999,20000,20547,20880,22105,22222,23023,23424,25000,25105,25565,27015,27017,28017,28080,29876,30001,32400,33338,33890,37215,37777,41795,45554,49151,49152,49153,49154,49155,50000,50050,50070,50100,51106,52869,55442,55553,55555,60001,60010,60030,60443,61613,61616,62078,64738",
			OutputPath: "/tmp/fscan_output.txt",
			ScanMode:   "normal",
			Proxy:      "",
		},
		GogoConfig: GogoConfig{
			Enabled:       true,
			Ports:         "top2,win,db,rce",
			Timeout:       5,
			Thread:        1000,
			Mode:          "default",
			EnableExploit: true,
			Verbose:       true,
			OutputPath:    "/tmp/gogo/",
		},
		AfrogConfig: AfrogConfig{
			Enabled: true,
			Threads: 50,
		},
		NucleiConfig: NucleiConfig{
			Enabled: true,
			Threads: 50,
		},
	}
}
