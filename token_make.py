'''
自定义jwt
    token
'''
import json
import base64
import time
import hmac

# 自定义异常类型

class JwtErr(Exception):
    def __init__(self, message):
        self.msg = message

    def __str__(self):
        return '<JwtErr>:%s' % self.msg



class Jwt:
    HEADER = {'alg':'HS256', 'typ':'JWT'}
    def __init__(self):
        pass

    # 加密生成token
    @staticmethod
    def encode(payload, key, exp=300):
        #生成header的b64加密串
            #生成header的json串,(字符串)
        json_header = json.dumps(Jwt.HEADER, separators=(',',':'), sort_keys=True)
            #生成header的base64加密串
        b64_header = Jwt.b64_encode(json_header.encode())#二进制

        #生成payload的b64加密串
        # 判断payload是否有exp属性
        if not payload.get('exp', ''):
            payload['exp'] = int(time.time()) + exp
        else:
            payload['exp'] = payload.get('exp') + int(time.time())
        json_payload = json.dumps(payload,separators=(',',':'), sort_keys=True)
        b64_payload = Jwt.b64_encode(json_payload.encode())

        # sign签名
        sign = b64_header + b'.' + b64_payload + key.encode()
        if type(key) is str:
            key = key.encode()
        h = hmac.new(key, sign, digestmod='SHA256')
        res = h.hexdigest()

        return b64_header + b'.' + b64_payload + b'.' + res.encode()

    # token验证
    @staticmethod
    def decode(token, key):
        b64_header, b64_payload, sign = token.split(b'.')

        #验证token是否合法
        new_sign_ = b64_header + b'.' + b64_payload + key.encode()
        if type(key) is str:
            key = key.encode()
        h = hmac.new(key, new_sign_, digestmod='SHA256')
        new_sign = h.hexdigest()
        if sign != new_sign.encode():
            raise JwtErr('Your token is wrongful')
        payload = json.loads(Jwt.b64_decode(b64_payload))

        #检验是否过期
        time_ = payload.get('exp')
        now = time.time()
        if now > time_:
            raise JwtErr('Your token is expired')

        return True

    # 去加密后的=
    @staticmethod
    def b64_encode(s):
        if type(s) is str:
            s = s.encode()
        return base64.urlsafe_b64encode(s).replace(b'=', b'')#二进制

    #还原去掉=的b64串
    @staticmethod
    def b64_decode(s):
        num = 4 - (len(s) % 4)
        s += b"="*num
        return base64.urlsafe_b64decode(s)


if __name__ == "__main__":
    payload = {'username':'xsw'}
    token = Jwt.encode(payload, key='abc23')
    print(len(token))

    # 验证
    # token = b'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1NjI0MDI4MDMsInVzZXjuYW1lIjoieHN3In0.538e0fb94463eb4e671cd27cbb4d0dd38d21dc2bf2358b2e45f03fc0792cbb2c'
    # print(Jwt.decode(token, key='abc23'))