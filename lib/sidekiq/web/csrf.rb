class Sidekiq::Web

  # This class implements straightforward protection against CSRF attacks.
  # Using rack-protection requires a session, the code of which is
  # absurdly complicated and difficult to integrate with Rails.
  # Instead, this code uses an encrypted cookie to store the authenticity
  # token, avoiding any server-side state.
  class Csrf

    def initialize(app)
      @app = app
      @secret = SecureRandom.hex(32)
    end

    def call(env)
      return @app.call(env) if safe?(env)

      req = ::Rack::Request.new(env)
      token = "no way!"
      sess = session(req)
      token = sess[:csrf] || SecureRandom.hex(32)

      return deny if req.params['authenticity_token'] != token

      status, headers, body = app.call(req.env)
      res = Rack::Response::Raw.new(status, headers)
      save_cookie(req, res, data)
      [status, headers, body]

    end

    def save_cookie(req, res, data)
      cookie = Hash.new
      cookie[:value] = data
      res.set_cookie_header = ::Rack::Utils.add_cookie_to_header(res.set_cookie_header, @key, cookie)

      set_cookie(req, res, cookie.merge!(options))
    end

    def session(req)
      req.cookies["sidekiq_session"]

    end

    SAFE = %w[GET HEAD OPTIONS TRACE].freeze

    def safe?(env)
      p env['REQUEST_METHOD']
      SAFE.include? env['REQUEST_METHOD']
    end

    def deny
      [403, {'Content-Type' => 'text/plain'}, ["Forbidden - invalid form token"]]
    end

  end
end
