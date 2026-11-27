import type { IncomingMessage, ServerResponse } from 'node:http'
import type { RegisterRouteOptions, WebServerLike } from './types.ts'

/**
 * Newer WebServer hosts authenticate each registered route before dispatch.
 * Older hosts ignore the route auth option, so keep their legacy cookie guard.
 */
export function registerAuthenticatedRoute(
  server: WebServerLike,
  route: RegisterRouteOptions,
  reject: (res: ServerResponse) => void,
): () => void {
  const register = server.register!.bind(server)
  if (typeof server.authPolicy === 'function' && typeof server.authorize === 'function') {
    return register({ ...route, auth: 'required' })
  }
  return register({
    ...route,
    handler(req, res) {
      if (!/(?:^|;\s*)dsh-auth-[^=]+=/.test(String((req as IncomingMessage).headers.cookie ?? ''))) {
        reject(res as ServerResponse)
        return
      }
      return route.handler(req, res)
    },
  })
}
