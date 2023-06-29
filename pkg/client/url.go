// Copyright 2023 The Keylime Authors
// SPDX-License-Identifier: Apache-2.0

package client

import "net/url"

// CloneURL clones the URL u. If it is nil, it returns nil.
func CloneURL(u *url.URL) *url.URL {
	if u == nil {
		return nil
	}
	u2 := new(url.URL)
	*u2 = *u
	if u.User != nil {
		u2.User = new(url.Userinfo)
		*u2.User = *u.User
	}
	return u2
}
