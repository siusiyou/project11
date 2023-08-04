from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

# 选择SM2椭圆曲线参数（此处以SM2曲线的参数为例）
curve_params = {
    'p': int('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF', 16),  # 曲线的有限域大小
    'a': int('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC', 16),  # 椭圆曲线参数a
   'b': int('28E9FA9E9D9F5E344D5A9E4BCF6509A7F397F515AB8F92DDBCBD414D940E93', 16),   # 椭圆曲线参数b
    'n': int('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123', 16),  # 基点G的阶
    'h': 1,  # 椭圆曲线的余因子
    'G': (int('32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE171', 16),  # 基点G的x坐标
          int('BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0', 16))  # 基点G的y坐标
}

# 生成SM2密钥对
def generate_key_pair():
    key = ECC.generate(curve='P-256')
    return {
        'private_key': key.d,
        'public_key': (key.pointQ.x(), key.pointQ.y())
    }

# SM2签名
def sm2_sign(private_key, message):
    key = ECC.construct(curve='P-256', d=private_key)
    h = SHA256.new(message)
    signer = DSS.new(key, 'fips-186-3')
    signature = signer.sign(h)
    return {
        'r': signature[0],
        's': signature[1]
    }

# SM2验签
def sm2_verify(public_key, message, signature):
    key = ECC.construct(curve='P-256', point_x=public_key[0], point_y=public_key[1])
    h = SHA256.new(message)
    verifier = DSS.new(key, 'fips-186-3')
    try:
        verifier.verify(h, (signature['r'], signature['s']))
        return True
    except ValueError:
        return False

# 测试代码
if __name__ == '__main__':
    # 生成密钥对
    key_pair = generate_key_pair()
    private_key = key_pair['private_key']
    public_key = key_pair['public_key']

    # 待签名消息
    message = b'This is a test message.'

    # 签名
    signature = sm2_sign(private_key, message)
    print('Signature:', signature)

    # 验签
    is_valid = sm2_verify(public_key, message, signature)
    if is_valid:
        print('Signature is valid.')
    else:
        print('Signature is invalid.')
