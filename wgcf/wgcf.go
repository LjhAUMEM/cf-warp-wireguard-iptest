package wgcf

import (
	"fmt"

	"github.com/ViRb3/wgcf/v2/cloudflare"
	"github.com/ViRb3/wgcf/v2/cmd/shared"
	"github.com/ViRb3/wgcf/v2/util"
	"github.com/ViRb3/wgcf/v2/wireguard"

	"github.com/spf13/viper"
)

func init() {
	viper.SetConfigFile("wgcf-account.toml")
	viper.ReadInConfig()
}

func Reg() {
	privateKey, _ := wireguard.NewPrivateKey()
	device, _ := cloudflare.Register(privateKey.Public(), "PC")
	viper.Set("private_key", privateKey.String())
	viper.Set("device_id", device.Id)
	viper.Set("access_token", device.Token)
	viper.Set("license_key", device.Account.License)
	viper.WriteConfig()
	ctx := shared.CreateContext()
	cloudflare.UpdateSourceBoundDeviceName(ctx, util.RandomHexString(3))
	cloudflare.UpdateSourceBoundDeviceActive(ctx, true)
}

func Get() (privateKey, publicKey, clientId string) {
	if viper.GetString("private_key") == "" {
		Reg()
	}
	ctx := shared.CreateContext()
	device, err := cloudflare.GetSourceDevice(ctx)
	if err != nil {
		fmt.Println("using default account")
		return "QNFmeFkgi2pUeI2JyyXjkxMBVC1Z+barKJEFYLvOxFE=", "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=", "wRiE"
	}
	cloudflare.UpdateSourceBoundDeviceActive(ctx, true)
	return viper.GetString("private_key"), device.Config.Peers[0].PublicKey, device.Config.ClientId
}
