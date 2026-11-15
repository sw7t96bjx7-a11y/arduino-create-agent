// Copyright 2026 Arduino Cloud Agent contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package main

import (
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

func isLoopbackHost(host string) bool {
	if strings.EqualFold(strings.TrimSuffix(host, "."), "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// loopbackHostGuard prevents an unrelated hostname from addressing a local-only
// agent through DNS rebinding. CORS alone does not reject requests whose Origin
// matches their Host. Explicit non-loopback bindings retain their existing
// behavior and require their own access controls.
func loopbackHostGuard(bindAddress string) gin.HandlerFunc {
	localOnly := isLoopbackHost(strings.TrimSuffix(strings.TrimPrefix(bindAddress, "["), "]"))
	return func(c *gin.Context) {
		if localOnly && !isLoopbackAuthority(c.Request.Host) {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		c.Next()
	}
}

func isLoopbackAuthority(authority string) bool {
	if authority == "" || strings.ContainsAny(authority, "@/\\?#% \t\r\n") {
		return false
	}
	host := authority
	if strings.HasPrefix(authority, "[") && strings.HasSuffix(authority, "]") {
		// An IPv6 literal without a port still requires brackets.
		host = authority[1 : len(authority)-1]
		if !strings.Contains(host, ":") {
			return false
		}
	} else if strings.Contains(authority, ":") {
		var port string
		var err error
		host, port, err = net.SplitHostPort(authority)
		if err != nil || port == "" {
			return false
		}
		for _, digit := range port {
			if digit < '0' || digit > '9' {
				return false
			}
		}
		portNumber, err := strconv.Atoi(port)
		if err != nil || portNumber < 1 || portNumber > 65535 {
			return false
		}
		if strings.HasPrefix(authority, "[") && !strings.Contains(host, ":") {
			return false
		}
	}
	return isLoopbackHost(host)
}
