package settings

import (
	"fmt"
	"time"

	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gosettings"
	"github.com/qdm12/gosettings/reader"
	"github.com/qdm12/gosettings/validate"
	"github.com/qdm12/gotree"
)

type VPN struct {
	// Type is the VPN type and can only be
	// 'openvpn' or 'wireguard'. It cannot be the
	// empty string in the internal state.
	Type      string    `json:"type"`
	Provider  Provider  `json:"provider"`
	AmneziaWg AmneziaWg `json:"amneziawg"`
	OpenVPN   OpenVPN   `json:"openvpn"`
	Wireguard Wireguard `json:"wireguard"`
	PMTUD     PMTUD     `json:"pmtud"`
	// UpCommand is the command to use when the VPN connection is up.
	// It can be the empty string to indicate not to run a command.
	// It cannot be nil in the internal state.
	UpCommand *string `json:"up_command"`
	// DownCommand is the command to use after the VPN connection goes down.
	// It can be the empty string to indicate to NOT run a command.
	// It cannot be nil in the internal state.
	DownCommand *string `json:"down_command"`
	// ReadyHook is a command or URL to call when the VPN connection is ready.
	// It can be the empty string to indicate not to run a hook.
	// It cannot be nil in the internal state.
	ReadyHook *string `json:"ready_hook"`
	// DisconnectHook is a command or URL to call on unexpected VPN disconnect.
	// It can be the empty string to indicate not to run a hook.
	// It cannot be nil in the internal state.
	DisconnectHook *string `json:"disconnect_hook"`
	// HookTimeout is the timeout for hook execution.
	// It cannot be nil in the internal state.
	HookTimeout *time.Duration `json:"hook_timeout"`
}

// Validate validates VPN settings, using the filter choices getter (aka servers data storage),
// and if IPv6 is supported or not.
// TODO v4 remove pointer for receiver (because of Surfshark).
func (v *VPN) Validate(filterChoicesGetter FilterChoicesGetter, ipv6Supported bool, warner Warner) (err error) {
	// Validate Type
	validVPNTypes := []string{vpn.AmneziaWg, vpn.OpenVPN, vpn.Wireguard}
	if err = validate.IsOneOf(v.Type, validVPNTypes...); err != nil {
		return fmt.Errorf("VPN type is not valid: %w", err)
	}

	err = v.Provider.validate(v.Type, filterChoicesGetter, warner)
	if err != nil {
		return fmt.Errorf("provider settings: %w", err)
	}

	switch v.Type {
	case vpn.AmneziaWg:
		err = v.AmneziaWg.validate(v.Provider.Name, ipv6Supported)
		if err != nil {
			return fmt.Errorf("AmneziaWG settings: %w", err)
		}
	case vpn.OpenVPN:
		err := v.OpenVPN.validate(v.Provider.Name)
		if err != nil {
			return fmt.Errorf("OpenVPN settings: %w", err)
		}
	case vpn.Wireguard:
		const amneziawg = false
		err := v.Wireguard.validate(v.Provider.Name, ipv6Supported, amneziawg)
		if err != nil {
			return fmt.Errorf("Wireguard settings: %w", err)
		}
	}

	err = v.PMTUD.validate()
	if err != nil {
		return fmt.Errorf("PMTUD settings: %w", err)
	}

	if *v.HookTimeout < 0 {
		return fmt.Errorf("hook timeout is negative: %s", *v.HookTimeout)
	}

	return nil
}

func (v *VPN) Copy() (copied VPN) {
	return VPN{
		Type:           v.Type,
		Provider:       v.Provider.copy(),
		AmneziaWg:      v.AmneziaWg.copy(),
		OpenVPN:        v.OpenVPN.copy(),
		Wireguard:      v.Wireguard.copy(),
		PMTUD:          v.PMTUD.copy(),
		UpCommand:      gosettings.CopyPointer(v.UpCommand),
		DownCommand:    gosettings.CopyPointer(v.DownCommand),
		ReadyHook:      gosettings.CopyPointer(v.ReadyHook),
		DisconnectHook: gosettings.CopyPointer(v.DisconnectHook),
		HookTimeout:    gosettings.CopyPointer(v.HookTimeout),
	}
}

func (v *VPN) OverrideWith(other VPN) {
	v.Type = gosettings.OverrideWithComparable(v.Type, other.Type)
	v.Provider.overrideWith(other.Provider)
	v.AmneziaWg.overrideWith(other.AmneziaWg)
	v.OpenVPN.overrideWith(other.OpenVPN)
	v.Wireguard.overrideWith(other.Wireguard)
	v.PMTUD.overrideWith(other.PMTUD)
	v.UpCommand = gosettings.OverrideWithPointer(v.UpCommand, other.UpCommand)
	v.DownCommand = gosettings.OverrideWithPointer(v.DownCommand, other.DownCommand)
	v.ReadyHook = gosettings.OverrideWithPointer(v.ReadyHook, other.ReadyHook)
	v.DisconnectHook = gosettings.OverrideWithPointer(v.DisconnectHook, other.DisconnectHook)
	v.HookTimeout = gosettings.OverrideWithPointer(v.HookTimeout, other.HookTimeout)
}

func (v *VPN) setDefaults() {
	v.Type = gosettings.DefaultComparable(v.Type, vpn.OpenVPN)
	v.Provider.setDefaults()
	v.AmneziaWg.setDefaults(v.Provider.Name)
	v.OpenVPN.setDefaults(v.Provider.Name)
	v.Wireguard.setDefaults(v.Provider.Name)
	v.PMTUD.setDefaults()
	v.UpCommand = gosettings.DefaultPointer(v.UpCommand, "")
	v.DownCommand = gosettings.DefaultPointer(v.DownCommand, "")
	v.ReadyHook = gosettings.DefaultPointer(v.ReadyHook, "")
	v.DisconnectHook = gosettings.DefaultPointer(v.DisconnectHook, "")
	const defaultHookTimeout = 30 * time.Second
	v.HookTimeout = gosettings.DefaultPointer(v.HookTimeout, defaultHookTimeout)
}

func (v VPN) String() string {
	return v.toLinesNode().String()
}

func (v VPN) toLinesNode() (node *gotree.Node) {
	node = gotree.New("VPN settings:")

	node.AppendNode(v.Provider.toLinesNode())

	switch v.Type {
	case vpn.AmneziaWg:
		node.AppendNode(v.AmneziaWg.toLinesNode())
	case vpn.OpenVPN:
		node.AppendNode(v.OpenVPN.toLinesNode())
	case vpn.Wireguard:
		node.AppendNode(v.Wireguard.toLinesNode())
	}
	node.AppendNode(v.PMTUD.toLinesNode())

	if *v.UpCommand != "" {
		node.Appendf("Up command: %s", *v.UpCommand)
	}
	if *v.DownCommand != "" {
		node.Appendf("Down command: %s", *v.DownCommand)
	}
	if *v.ReadyHook != "" {
		node.Appendf("Ready hook: %s", *v.ReadyHook)
	}
	if *v.DisconnectHook != "" {
		node.Appendf("Disconnect hook: %s", *v.DisconnectHook)
	}
	node.Appendf("Hook timeout: %s", *v.HookTimeout)

	return node
}

func (v *VPN) read(r *reader.Reader) (err error) {
	v.Type = r.String("VPN_TYPE")

	err = v.Provider.read(r, v.Type)
	if err != nil {
		return fmt.Errorf("VPN provider: %w", err)
	}

	err = v.AmneziaWg.read(r)
	if err != nil {
		return fmt.Errorf("AmneziaWG: %w", err)
	}

	err = v.OpenVPN.read(r)
	if err != nil {
		return fmt.Errorf("OpenVPN: %w", err)
	}

	const amneziawg = false
	err = v.Wireguard.read(r, amneziawg)
	if err != nil {
		return fmt.Errorf("wireguard: %w", err)
	}

	err = v.PMTUD.read(r)
	if err != nil {
		return fmt.Errorf("PMTUD: %w", err)
	}

	v.UpCommand = r.Get("VPN_UP_COMMAND", reader.ForceLowercase(false))

	v.DownCommand = r.Get("VPN_DOWN_COMMAND", reader.ForceLowercase(false))

	v.ReadyHook = r.Get("VPN_READY_HOOK", reader.ForceLowercase(false))

	v.DisconnectHook = r.Get("VPN_DISCONNECT_HOOK", reader.ForceLowercase(false))

	v.HookTimeout, err = r.DurationPtr("VPN_HOOK_TIMEOUT")
	if err != nil {
		return fmt.Errorf("reading hook timeout: %w", err)
	}

	return nil
}
