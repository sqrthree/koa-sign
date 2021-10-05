const querystring = require('querystring')
const crypto = require('crypto')
const Koa = require('koa')
const bodyParser = require('koa-bodyparser')
const request = require('supertest')
const test = require('ava')

const { signMiddleware } = require('../dist/index')

/**
 * Disable console
 */
console.log = console.debug = () => ''

const app = new Koa()

const secret = 'secret'
const getSecret = () => secret

app.use(bodyParser())
app.use(
  signMiddleware({
    secret: getSecret,
  })
)

app.use((ctx) => {
  ctx.body = 'success'
})

test('should respond 500 with SECRET_INVALID due to invalid secret', async (t) => {
  const localApp = new Koa()

  localApp.silent = true

  localApp.use(
    signMiddleware({
      secret: () => '',
    })
  )

  const timestamp = Date.now()

  const response = await request(localApp.listen())
    .get(`/?timestamp=${timestamp}`)
    .expect(500)

  t.is(response.serverError, true)
})

test('should respond 400 without timestamp', async (t) => {
  const response = await request(app.listen()).get('/').expect(400)

  t.is(response.error.text, 'Outdated request')
})

test('should respond 400 with outdated timestamp', async (t) => {
  const response = await request(app.listen()).get('/?timestamp=0').expect(400)

  t.is(response.error.text, 'Outdated request')
})

test('should respond 401 with invalid signature in query', async (t) => {
  const timestamp = Date.now()
  const query = querystring.stringify({
    a: 1,
    timestamp,
    nonce: 'nonce',
    signature: 'a',
  })

  const response = await request(app.listen()).get(`/?${query}`).expect(401)

  t.is(response.error.text, 'Unexpected signature')
})

test('should respond 200 with valid signature in query', async (t) => {
  const timestamp = Date.now()
  const signature = crypto
    .createHash('md5')
    .update(`a=1&nonce=nonce&secret=${secret}&timestamp=${timestamp}`)
    .digest('hex')

  const query = querystring.stringify({
    a: 1,
    nonce: 'nonce',
    timestamp,
    signature,
  })

  const response = await request(app.listen()).get(`/?${query}`).expect(200)

  t.is(response.text, 'success')
})

test('should respond 401 with invalid signature in body', async (t) => {
  const timestamp = Date.now()

  const response = await request(app.listen())
    .post('/')
    .send({
      a: 1,
      timestamp,
      nonce: 'nonce',
      signature: 'a',
    })
    .expect(401)

  t.is(response.error.text, 'Unexpected signature')
})

test('should respond 200 with valid signature in body', async (t) => {
  const timestamp = Date.now()
  const signature = crypto
    .createHash('md5')
    .update(`a=1&nonce=nonce&secret=${secret}&timestamp=${timestamp}`)
    .digest('hex')

  const response = await request(app.listen())
    .post('/')
    .send({
      a: 1,
      timestamp,
      nonce: 'nonce',
      signature,
    })
    .expect(200)

  t.is(response.text, 'success')
})

test('should respond 200 with empty value in body', async (t) => {
  const timestamp = Date.now()
  const signature = crypto
    .createHash('md5')
    .update(`a=1&nonce=nonce&secret=${secret}&timestamp=${timestamp}`)
    .digest('hex')

  const response = await request(app.listen())
    .post('/')
    .send({
      a: 1,
      b: '',
      timestamp,
      nonce: 'nonce',
      signature,
    })
    .expect(200)

  t.is(response.text, 'success')
})

test('should respond 200 with static file request', async (t) => {
  let response = await request(app.listen()).post('/a.png').expect(200)

  t.is(response.text, 'success')

  response = await request(app.listen()).post('/a.css').expect(200)

  t.is(response.text, 'success')
})
