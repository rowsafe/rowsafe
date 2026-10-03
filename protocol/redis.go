package protocol

// redisFeatures are what Redis supports (EngineCapabilities). Redis and
// Valkey share the agent package internal/engine/redis. Every flag is off
// until the agent and the control plane both handle the feature; with
// Backups off the control plane refuses to add a Redis database at all.
var redisFeatures = EngineFeatures{}

// valkeyFeatures are Redis's: Valkey is a fork of Redis 7.2 that speaks the
// same protocol and keeps the same files.
var valkeyFeatures = redisFeatures
