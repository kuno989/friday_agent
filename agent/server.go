package agent

import (
	"github.com/google/wire"
	"github.com/kuno989/friday_agent/agent/pkg"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/spf13/viper"
)

var (
	DefaultServerConfig = ServerConfig{
		Debug: true,
	}
	ServerProviderSet = wire.NewSet(NewServer, ProvideServerConfig)
)

type ServerConfig struct {
	Debug          bool     `mapstructure:"debug"`
	URI            string   `mapstructure:"uri"`
	AgentPort      string   `mapstructure:"agent_port"`
	BrokerURI      string   `mapstructure:"broker_uri"`
	BrokerPort     string   `mapstructure:"broker_port"`
	AllowedOrigins []string `mapstructure:"allowed_origins"`
	MaxFileSize    int64    `mapstructure:"maxFileSize"`
	Volume         string   `mapstructure:"volume"`
}

func ProvideServerConfig(cfg *viper.Viper) (ServerConfig, error) {
	sc := DefaultServerConfig
	err := cfg.Unmarshal(&sc)
	return sc, err
}

type Server struct {
	*echo.Echo
	Config ServerConfig
	minio  *pkg.Minio
}

func NewServer(cfg ServerConfig, minio *pkg.Minio) *Server {
	s := &Server{
		Echo:   echo.New(),
		Config: cfg,
		minio:  minio,
	}
	s.HideBanner = true
	s.HidePort = true
	var allowedOrigins []string
	if cfg.Debug {
		allowedOrigins = append(cfg.AllowedOrigins, "http://localhost:3000", "*")
	} else {
		if len(cfg.AllowedOrigins) == 0 {
			allowedOrigins = []string{"http://localhost:3000"}
		} else {
			allowedOrigins = cfg.AllowedOrigins
		}
	}
	s.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins:     allowedOrigins,
		AllowCredentials: true,
		AllowHeaders:     []string{"Content-Type", "Authorization", "Access-Control-allow-Methods", "Access-Control-Allow-Origin", "Access-Control-Allow-Headers"},
	}))
	s.RegisterHandlers()
	return s
}
func (s *Server) RegisterHandlers() {
	api := s.Group("/api")
	api.GET("/", s.index)
	api.GET("/system", s.system)
	api.POST("/download", s.malwareDownload)
	api.POST("/start", s.startAnalysis)
}
