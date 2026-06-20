package wireguard

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func ConfigureDevice(client *wgctrl.Client, settings Settings) (err error) {
	deviceConfig, err := makeDeviceConfig(settings)
	if err != nil {
		return fmt.Errorf("making device configuration: %w", err)
	}

	err = client.ConfigureDevice(settings.InterfaceName, deviceConfig)
	if err != nil {
		return fmt.Errorf("configuring device: %w", err)
	}

	return nil
}

func makeDeviceConfig(settings Settings) (config wgtypes.Config, err error) {
	privateKey, err := wgtypes.ParseKey(settings.PrivateKey)
	if err != nil {
		return config, errors.New("cannot parse private key")
	}

	firewallMark := int(settings.FirewallMark)

	var peerConfigs []wgtypes.PeerConfig
	if len(settings.Peers) > 0 {
		peerConfigs, err = makeMultiPeerConfigs(settings.Peers)
		if err != nil {
			return config, err
		}
	} else {
		peerConfigs, err = makeSinglePeerConfig(settings)
		if err != nil {
			return config, err
		}
	}

	config = wgtypes.Config{
		PrivateKey:   &privateKey,
		ReplacePeers: true,
		FirewallMark: &firewallMark,
		Peers:        peerConfigs,
	}

	return config, nil
}

func makeSinglePeerConfig(settings Settings) (peers []wgtypes.PeerConfig, err error) {
	publicKey, err := wgtypes.ParseKey(settings.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("cannot parse public key: %s", settings.PublicKey)
	}

	var preSharedKey *wgtypes.Key
	if settings.PreSharedKey != "" {
		preSharedKeyValue, err := wgtypes.ParseKey(settings.PreSharedKey)
		if err != nil {
			return nil, errors.New("cannot parse pre-shared key")
		}
		preSharedKey = &preSharedKeyValue
	}

	var persistentKeepaliveInterval *time.Duration
	if settings.PersistentKeepaliveInterval > 0 {
		persistentKeepaliveInterval = new(time.Duration)
		*persistentKeepaliveInterval = settings.PersistentKeepaliveInterval
	}

	peers = []wgtypes.PeerConfig{
		{
			PublicKey:    publicKey,
			PresharedKey: preSharedKey,
			AllowedIPs: []net.IPNet{
				{
					IP:   net.IPv4(0, 0, 0, 0),
					Mask: []byte{0, 0, 0, 0},
				},
				{
					IP:   net.IPv6zero,
					Mask: []byte(net.IPv6zero),
				},
			},
			PersistentKeepaliveInterval: persistentKeepaliveInterval,
			ReplaceAllowedIPs:           true,
			Endpoint: &net.UDPAddr{
				IP:   settings.Endpoint.Addr().AsSlice(),
				Port: int(settings.Endpoint.Port()),
			},
		},
	}

	return peers, nil
}

func makeMultiPeerConfigs(peers []Peer) (peerConfigs []wgtypes.PeerConfig, err error) {
	peerConfigs = make([]wgtypes.PeerConfig, len(peers))
	for i, peer := range peers {
		publicKey, err := wgtypes.ParseKey(peer.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("cannot parse public key for peer %d: %s", i, peer.PublicKey)
		}

		allowedIPs := make([]net.IPNet, len(peer.AllowedIPs))
		for j, allowedIP := range peer.AllowedIPs {
			allowedIPs[j] = net.IPNet{
				IP:   allowedIP.Addr().AsSlice(),
				Mask: net.CIDRMask(allowedIP.Bits(), allowedIP.Addr().BitLen()),
			}
		}

		var persistentKeepaliveInterval *time.Duration
		if peer.PersistentKeepaliveInterval > 0 {
			persistentKeepaliveInterval = new(time.Duration)
			*persistentKeepaliveInterval = peer.PersistentKeepaliveInterval
		}

		peerConfigs[i] = wgtypes.PeerConfig{
			PublicKey:                   publicKey,
			AllowedIPs:                  allowedIPs,
			PersistentKeepaliveInterval: persistentKeepaliveInterval,
			ReplaceAllowedIPs:           true,
			Endpoint: &net.UDPAddr{
				IP:   peer.Endpoint.Addr().AsSlice(),
				Port: int(peer.Endpoint.Port()),
			},
		}
	}

	return peerConfigs, nil
}

func allIPv4() (prefix netip.Prefix) {
	const bits = 0
	return netip.PrefixFrom(netip.IPv4Unspecified(), bits)
}

func allIPv6() (prefix netip.Prefix) {
	const bits = 0
	return netip.PrefixFrom(netip.IPv6Unspecified(), bits)
}
