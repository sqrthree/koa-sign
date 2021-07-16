import crypto from 'crypto'
import Koa from 'koa'
import unless from 'koa-less'
import _ from 'lodash'

const md5 = function md5(value: string): string {
  const hash = crypto.createHash('md5')

  hash.update(value)

  const result = hash.digest('hex')

  return result
}

const isEmpty = function isEmpty(value: any): boolean {
  return value === undefined || value === null || value === ''
}

const serialize = function serialize(data: Record<string, any>): string {
  const keys = Object.keys(data)
  const sortedKeys = keys.sort()

  let result = ''

  for (let i = 0, len = sortedKeys.length; i < len; i += 1) {
    const key = sortedKeys[i]
    const value = data[key]
    const empty = isEmpty(value)

    if (!empty) {
      if (result) {
        result += '&'
      }

      result += `${key}=${value}`
    }
  }

  return result
}

const sign = function sign(data: Record<string, any>): string {
  const str = serialize(data)
  const result = md5(str)

  return result
}

const signData = function signData(
  secret: string,
  data: Record<string, any>
): string {
  const payload = _.assign(_.omit(data, 'signature'), {
    secret,
  })
  const signature = sign(payload)

  return signature
}

const outdated = function outdated(timestamp: number, min = 5): boolean {
  const now = Date.now()
  const diff = Math.abs(now - timestamp)
  const m = 60000 // 60 * 1000
  const minutes = diff / m

  return minutes > min
}

interface SignMiddlewareOptions {
  secret: (ctx: Koa.Context) => string | Promise<string>
}

export function signMiddleware(options: SignMiddlewareOptions): Koa.Middleware {
  const middleware = async function middleware(
    ctx: Koa.Context,
    next: Koa.Next
  ): Promise<any> {
    const { method, query } = ctx
    const logger = ctx.logger || console
    const { body } = ctx.request
    const hasQuery = !_.isEmpty(query)
    const hasBody = !_.isEmpty(body)

    const timestamp = _.get(query, 'timestamp') || _.get(body, 'timestamp') || 0
    const isOutdated = outdated(timestamp)

    if (isOutdated) {
      ctx.throw(400, 'Outdated request', {
        code: 'REQUEST_OUTDATED',
      })
    }

    const secret: string = await options.secret(ctx)

    if (!secret) {
      ctx.throw(401, 'Invalid secret', {
        code: 'SECRET_INVALID',
      })
    }

    if (method === 'GET' || method === 'DELETE' || hasQuery) {
      const signature: string = query ? (query.signature as string) : ''
      const expect = signData(secret, query)

      if (signature !== expect) {
        logger.debug(
          { expect, got: signature },
          'Invalid signature for the params of request.'
        )

        ctx.throw(401, 'Unexpected signature', {
          code: 'SIGNATURE_UNEXPECTED',
        })
      }
    }

    if (
      method === 'POST' ||
      method === 'PUT' ||
      method === 'PATCH' ||
      hasBody
    ) {
      const signature = body ? body.signature : ''
      const expect = signData(secret, body)

      if (signature !== expect) {
        logger.debug(
          { expect, got: signature },
          'Invalid signature for the body of request.'
        )

        ctx.throw(401, 'Unexpected signature', {
          code: 'SIGNATURE_UNEXPECTED',
        })
      }
    }

    return next()
  }

  middleware.unless = unless

  return middleware
}
