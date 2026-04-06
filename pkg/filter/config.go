package filter

// FilterConfig holds the Lua scripts and rate limit settings for one filter set.
type FilterConfig struct {
	InputMcast  string
	OutputMcast string
	InputRoute  string
	OutputRoute string
	RateLimit   RateLimitConfig
}

// RateLimitConfig specifies rate limits for multicast packets.
type RateLimitConfig struct {
	PerMAC    float64 // pps per source MAC, default 64
	PerClient float64 // pps total per client, default 1000
}

// FilterConfigFile is the YAML-parseable form.
type FilterConfigFile struct {
	InputMcast      string          `yaml:"input_mcast"`
	OutputMcast     string          `yaml:"output_mcast"`
	InputRoute      string          `yaml:"input_route"`
	OutputRoute     string          `yaml:"output_route"`
	InputMcastFile  string          `yaml:"input_mcast_file"`
	OutputMcastFile string          `yaml:"output_mcast_file"`
	InputRouteFile  string          `yaml:"input_route_file"`
	OutputRouteFile string          `yaml:"output_route_file"`
	RateLimit       RateLimitFile   `yaml:"rate_limit"`
}

// RateLimitFile is the YAML-parseable rate limit config.
type RateLimitFile struct {
	PerMAC    *float64 `yaml:"per_mac"`
	PerClient *float64 `yaml:"per_client"`
}

// DefaultFilterConfig returns a FilterConfig with default scripts and rate limits.
func DefaultFilterConfig() *FilterConfig {
	return &FilterConfig{
		InputMcast:  DefaultMcastScript,
		OutputMcast: DefaultMcastScript,
		InputRoute:  DefaultRouteScript,
		OutputRoute: DefaultRouteScript,
		RateLimit: RateLimitConfig{
			PerMAC:    DefaultPerMACRate,
			PerClient: DefaultPerClientRate,
		},
	}
}

// ParseFilterConfigFile converts a FilterConfigFile to FilterConfig, filling defaults.
func ParseFilterConfigFile(f *FilterConfigFile) *FilterConfig {
	cfg := DefaultFilterConfig()

	if f == nil {
		return cfg
	}

	if f.InputMcast != "" {
		cfg.InputMcast = f.InputMcast
	} else if f.InputMcastFile != "" {
		cfg.InputMcast = "@" + f.InputMcastFile
	}

	if f.OutputMcast != "" {
		cfg.OutputMcast = f.OutputMcast
	} else if f.OutputMcastFile != "" {
		cfg.OutputMcast = "@" + f.OutputMcastFile
	}

	if f.InputRoute != "" {
		cfg.InputRoute = f.InputRoute
	} else if f.InputRouteFile != "" {
		cfg.InputRoute = "@" + f.InputRouteFile
	}

	if f.OutputRoute != "" {
		cfg.OutputRoute = f.OutputRoute
	} else if f.OutputRouteFile != "" {
		cfg.OutputRoute = "@" + f.OutputRouteFile
	}

	if f.RateLimit.PerMAC != nil {
		cfg.RateLimit.PerMAC = *f.RateLimit.PerMAC
	}
	if f.RateLimit.PerClient != nil {
		cfg.RateLimit.PerClient = *f.RateLimit.PerClient
	}

	return cfg
}

// FilterSet holds the four filter engines for one endpoint (client or per-client on controller).
type FilterSet struct {
	InputMcast  *FilterEngine
	OutputMcast *FilterEngine
	InputRoute  *FilterEngine
	OutputRoute *FilterEngine
}

// NewFilterSet creates a FilterSet from a FilterConfig.
func NewFilterSet(cfg *FilterConfig) (*FilterSet, error) {
	if cfg == nil {
		cfg = DefaultFilterConfig()
	}

	inputMcast, err := NewFilterEngine(cfg.InputMcast, &cfg.RateLimit)
	if err != nil {
		return nil, err
	}
	outputMcast, err := NewFilterEngine(cfg.OutputMcast, &cfg.RateLimit)
	if err != nil {
		return nil, err
	}
	inputRoute, err := NewFilterEngine(cfg.InputRoute, nil)
	if err != nil {
		return nil, err
	}
	outputRoute, err := NewFilterEngine(cfg.OutputRoute, nil)
	if err != nil {
		return nil, err
	}

	return &FilterSet{
		InputMcast:  inputMcast,
		OutputMcast: outputMcast,
		InputRoute:  inputRoute,
		OutputRoute: outputRoute,
	}, nil
}

// Close releases all Lua VMs.
func (fs *FilterSet) Close() {
	if fs == nil {
		return
	}
	fs.InputMcast.Close()
	fs.OutputMcast.Close()
	fs.InputRoute.Close()
	fs.OutputRoute.Close()
}
