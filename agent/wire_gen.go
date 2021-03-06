// Code generated by Wire. DO NOT EDIT.

//go:generate go run github.com/google/wire/cmd/wire
//go:build !wireinject
// +build !wireinject

package agent

import (
	"context"
	"github.com/kuno989/friday_agent/agent/pkg"
	"github.com/spf13/viper"
)

// Injectors from wire.go:

func InitializeServer(ctx context.Context, cfg *viper.Viper) (*Server, func(), error) {
	serverConfig, err := ProvideServerConfig(cfg)
	if err != nil {
		return nil, nil, err
	}
	minioConfig, err := pkg.ProvideMinioConfig(cfg)
	if err != nil {
		return nil, nil, err
	}
	minio, err := pkg.NewMinio(minioConfig)
	if err != nil {
		return nil, nil, err
	}
	server := NewServer(serverConfig, minio)
	return server, func() {
	}, nil
}
