package dockerctl

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
)

// Re-creating the agent container with the same configuration and only the
// image changed, as `docker compose up` does when the image changed.
//
// Docker's inspect answer has the container's whole configuration: Config
// (environment, command, labels, user...), HostConfig (mounts, network
// mode, restart policy, capabilities, limits...) and the networks it is
// attached to. The new container gets all of it, except what came from the
// old image rather than from the operator: Docker merged the image's
// environment, labels, command, entrypoint, working directory, health
// check, ports and volumes into Config when it created the container, and
// those must come from the new image now. A value equal to the old image's
// is the old image's (as Watchtower and compose treat it).

// inspected is the part of the inspect answer the copy needs, kept raw so
// that settings this code doesn't know about are copied too.
type inspected struct {
	ID              string                     `json:"Id"`
	Name            string                     `json:"Name"`
	Image           string                     `json:"Image"`
	Config          map[string]json.RawMessage `json:"Config"`
	HostConfig      map[string]json.RawMessage `json:"HostConfig"`
	Mounts          []mountPoint               `json:"Mounts"`
	NetworkSettings struct {
		Networks map[string]map[string]json.RawMessage `json:"Networks"`
	} `json:"NetworkSettings"`
}

type mountPoint struct {
	Type        string `json:"Type"`
	Name        string `json:"Name"`
	Destination string `json:"Destination"`
	RW          bool   `json:"RW"`
}

// fromImage are the Config fields Docker fills from the image when the
// container doesn't set them.
var fromImage = []string{"Cmd", "Entrypoint", "WorkingDir", "User", "Healthcheck", "ExposedPorts", "Volumes",
	"StopSignal", "Shell", "OnBuild", "ArgsEscaped"}

// replacement builds the body of POST /containers/create for a copy of the
// container described by raw (its inspect answer) running image, given the
// old image's inspect answer.
func replacement(raw []byte, old imageJSON, image string) (map[string]any, error) {
	var c inspected
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("reading the agent container's configuration: %w", err)
	}
	if c.Config == nil || c.HostConfig == nil {
		return nil, errors.New("Docker's answer has no configuration for the agent container")
	}
	cfg := map[string]any{}
	for k, v := range c.Config {
		cfg[k] = v
	}
	img := old.Config
	same := func(k string) bool {
		a, b := c.Config[k], img[k]
		return jsonEqual(a, b)
	}
	for _, k := range fromImage {
		if _, ok := c.Config[k]; ok && same(k) {
			delete(cfg, k)
		}
	}
	// Environment and labels: drop the entries the old image set.
	var env, imgEnv []string
	_ = json.Unmarshal(c.Config["Env"], &env)
	_ = json.Unmarshal(img["Env"], &imgEnv)
	var keep []string
	for _, e := range env {
		if !contains(imgEnv, e) {
			keep = append(keep, e)
		}
	}
	cfg["Env"] = keep
	var labels, imgLabels map[string]string
	_ = json.Unmarshal(c.Config["Labels"], &labels)
	_ = json.Unmarshal(img["Labels"], &imgLabels)
	kept := map[string]string{}
	for k, v := range labels {
		if iv, ok := imgLabels[k]; !ok || iv != v {
			kept[k] = v
		}
	}
	cfg["Labels"] = kept
	// A hostname Docker made up from the old container's ID goes; one the
	// operator set (compose's hostname:, the name Rowsafe shows) stays.
	var hostname string
	_ = json.Unmarshal(c.Config["Hostname"], &hostname)
	if hostname != "" && len(c.ID) >= 12 && hostname == c.ID[:12] {
		delete(cfg, "Hostname")
	}
	delete(cfg, "MacAddress") // deprecated here, and must not clash
	delete(cfg, "Image")
	cfg["Image"] = image

	host := map[string]any{}
	for k, v := range c.HostConfig {
		host[k] = v
	}
	// Anonymous volumes (an image VOLUME the operator didn't mount) belong
	// to the old container: hand them over, as compose does, so nothing in
	// them is lost.
	if extra := anonymousVolumes(c); len(extra) > 0 {
		var mounts []any
		if m, ok := c.HostConfig["Mounts"]; ok {
			_ = json.Unmarshal(m, &mounts)
		}
		for _, m := range extra {
			mounts = append(mounts, m)
		}
		host["Mounts"] = mounts
	}

	body := cfg
	body["HostConfig"] = host
	var mode string
	_ = json.Unmarshal(c.HostConfig["NetworkMode"], &mode)
	if eps := endpoints(c, mode); len(eps) > 0 {
		body["NetworkingConfig"] = map[string]any{"EndpointsConfig": eps}
	}
	return body, nil
}

// anonymousVolumes are the old container's volume mounts that neither its
// binds nor its mounts name.
func anonymousVolumes(c inspected) []map[string]any {
	covered := map[string]bool{}
	var binds []string
	_ = json.Unmarshal(c.HostConfig["Binds"], &binds)
	for _, b := range binds {
		parts := strings.Split(b, ":")
		if len(parts) >= 2 {
			covered[parts[1]] = true
		}
	}
	var mounts []struct {
		Target string `json:"Target"`
	}
	_ = json.Unmarshal(c.HostConfig["Mounts"], &mounts)
	for _, m := range mounts {
		covered[m.Target] = true
	}
	var out []map[string]any
	for _, m := range c.Mounts {
		if m.Type != "volume" || m.Name == "" || covered[m.Destination] {
			continue
		}
		out = append(out, map[string]any{"Type": "volume", "Source": m.Name, "Target": m.Destination, "ReadOnly": !m.RW})
	}
	return out
}

// endpoints are the networks to attach the new container to, with the
// operator's settings (aliases, fixed addresses, links), not the old
// container's addresses.
func endpoints(c inspected, mode string) map[string]any {
	if mode == "host" || mode == "none" || strings.HasPrefix(mode, "container:") {
		return nil
	}
	out := map[string]any{}
	for name, ep := range c.NetworkSettings.Networks {
		e := map[string]any{}
		var aliases []string
		_ = json.Unmarshal(ep["Aliases"], &aliases)
		var keep []string
		for _, a := range aliases {
			if a != c.ID && (len(c.ID) < 12 || a != c.ID[:12]) {
				keep = append(keep, a)
			}
		}
		if len(keep) > 0 {
			e["Aliases"] = keep
		}
		for _, k := range []string{"IPAMConfig", "Links", "DriverOpts"} {
			if v, ok := ep[k]; ok && string(v) != "null" {
				e[k] = v
			}
		}
		out[name] = e
	}
	return out
}

func jsonEqual(a, b json.RawMessage) bool {
	if len(a) == 0 || string(a) == "null" {
		return len(b) == 0 || string(b) == "null"
	}
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	return reflect.DeepEqual(x, y)
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
