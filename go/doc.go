// Package casdoor is the Grow Codes SDK for Casdoor.
//
// Create a client from the environment (GROW_CASDOOR_URL,
// GROW_CASDOOR_TOKEN, ...) or from a Config literal:
//
//	client, err := casdoor.NewClientFromEnv()
//	if err != nil {
//		return err
//	}
//	defer client.Close()
//	status, err := client.Health(ctx)
//
// Every error is an *Error; compare codes with errors.Is against the Err*
// sentinels (errors.Is(err, casdoor.ErrNotFound)). Credentials are wrapped in
// Secret and never appear in errors, hooks or logs.
//
// Casdoor is a trademark of its owner (Casdoor / Casbin organization); this package is not
// affiliated with or endorsed by it.
package casdoor
