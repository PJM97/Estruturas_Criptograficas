from cryptography.hazmat.primitives import padding

def pad(m):
	padder = padding.PKCS7(128).padder()
	padded_data = padder.update(m)
	padded_data +=padder.finalize()
	return padded_data

def unpad(m):
	unpadder = padding.PKCS7(128).unpadder()
	data = unpadder.update(m)
	return data + unpadder.finalize()


# inn = input(">").encode()
# p = pad(inn)
# print(p)
# print(unpad(p))




from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa
private_key = dsa.generate_private_key(
    key_size=1024,
    backend=default_backend()
)
data = b"this is some data I'd like to sign"
data2 = b"this is some data I'd like to sogn"
signature = private_key.sign(
    data,
    hashes.SHA256()
)


public_key = private_key.public_key()
r = public_key.verify(
    signature,
    data,
    hashes.SHA256()
)


print(type(private_key),private_key)
print(type(data),data)
print(type(signature),signature)
print(type(public_key),public_key)
print(type(r),r)

public_key = private_key.public_key()
r = public_key.verify(
    signature,
    data2,
    hashes.SHA256()
)




