# oidc-rp

[![](https://github.com/pkoenig10/oidc-rp/actions/workflows/ci.yml/badge.svg)][actions]

An [OpenID Connect](https://openid.net/connect/) Relying Party server that can be used with the [NGINX](https://www.nginx.com/) [auth_request module](http://nginx.org/en/docs/http/ngx_http_auth_request_module.html).

Users are authenticated using the configured OpenID Provider and authorized using the provided [configuration](#configuration). Session information is stored as a signed JWT in a cookie.

## Endpoints

- #### `/auth`

    Performs authentication and authorization. The user's email address is returned in the `X-Subject` response header.

    **Query parameters:**

    | Name | Required | Description |
    | :-: | :-: | :- |
    | `group` | No | The group name to use for authorization. |

    **Status codes:**

    | Status | Description |
    | :-: | :- |
    | 200 | The user is authenticated and authorized. |
    | 401 | The user is not authenticated. The user should be redirected to the login endpoint. |
    | 403 | The user is authenticated but not authorized. This indicates that the user is not a member of the given group. |

- #### `/login`

    Starts the [OpenID Connect Authorization Code Flow](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth).

    **Query parameters:**

    | Name | Required | Description |
    | :-: | :-: | :- |
    | `redirect` | No | The redirect URL to redirect to after a successful login. |

    **Status codes:**

    | Status | Description |
    | :-: | :- |
    | 302 | Redirects to the [OpenID Provider Authorization Endpoint](https://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint). |

- #### `/logout`

    Performs logout.

    **Status codes:**

    | Status | Description |
    | :-: | :- |
    | 200 | The user was successfully logged out. |

- #### `/callback`

    Completes the [OpenID Connect Authorization Code Flow](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth). The OpenID Provider should be configured with this endpoint as the callback URL.

    **Status codes:**

    | Status | Description |
    | :-: | :- |
    | 200 | The user was successfully logged in and no redirect URL was given. |
    | 302 | The user was successfully logged in and redirects to the given redirect URL. |
    | 400 | The request was invalid. |

## Configuration

Configuration is provided using command-line flags and a YAML configuration file.

Detailed usage information is available using the `-help` flag.

### Configuration file

- `groups`

    Group memberships to use for authorization.

#### Example

```yaml
groups:
  group1:
    - user1@example.com
  group2:
    - user1@example.com
    - user2@example.com
```

[actions]: https://github.com/pkoenig10/oidc-rp/actions
