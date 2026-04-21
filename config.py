# config.py

# --- OTA Public Keys ---
OTA_PUBLIC_KEYS = {
    "cn": """-----BEGIN RSA PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApXYGXQpNL7gmMzzvajHa
oZIHQQvBc2cOEhJc7/tsaO4sT0unoQnwQKfNQCuv7qC1Nu32eCLuewe9LSYhDXr9
KSBWjOcCFXVXteLO9WCaAh5hwnUoP/5/Wz0jJwBA+yqs3AaGLA9wJ0+B2lB1vLE4
FZNE7exUfwUc03fJxHG9nCLKjIZlrnAAHjRCd8mpnADwfkCEIPIGhnwq7pdkbamZ
coZfZud1+fPsELviB9u447C6bKnTU4AaMcR9Y2/uI6TJUTcgyCp+ilgU0JxemrSI
PFk3jbCbzamQ6Shkw/jDRzYoXpBRg/2QDkbq+j3ljInu0RHDfOeXf3VBfHSnQ66H
CwIDAQAB
-----END RSA PUBLIC KEY-----""",
    "eu": """-----BEGIN RSA PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAh8/EThsK3f0WyyPgrtXb
/D0Xni6UZNppaQHUqHWo976cybl92VxmehE0ISObnxERaOtrlYmTPIxkVC9MMueD
vTwZ1l0KxevZVKU0sJRxNR9AFcw6D7k9fPzzpNJmhSlhpNbt3BEepdgibdRZbacF
3NWy3ejOYWHgxC+I/Vj1v7QU5gD+1OhgWeRDcwuV4nGY1ln2lvkRj8EiJYXfkSq/
wUI5AvPdNXdEqwou4FBcf6mD84G8pKDyNTQwwuk9lvFlcq4mRqgYaFg9DAgpDgqV
K4NTJWM7tQS1GZuRA6PhupfDqnQExyBFhzCefHkEhcFywNyxlPe953NWLFWwbGvF
KwIDAQAB
-----END RSA PUBLIC KEY-----""",
    "in": """-----BEGIN RSA PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwYtghkzeStC9YvAwOQmW
ylbp74Tj8hhi3f9IlK7A/CWrGbLgzz/BeKxNb45zBN8pgaaEOwAJ1qZQV5G4nPro
WCPOP1ro1PkemFJvw/vzOOT5uN0ADnHDzZkZXCU/knxqUSfLcwQlHXsYhNsAm7uO
KjY9YXF4zWzYN0eFPkML3Pj/zg7hl/ov9clB2VeyI1/blMHFfcNA/fvqDTENXcNB
IhgJvXiCpLcZqp+aLZPC5AwY/sCb3j5jTWer0Rk0ZjQBZE1AncwYvUx4mA65U59c
WpTyl4c47J29MsQ66hqWv6eBHlDNZSEsQpHePUqgsf7lmO5Wd7teB8ugQki2oz1Y
5QIDAQAB
-----END RSA PUBLIC KEY-----""",
    "sg": """-----BEGIN RSA PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkA980wxi+eTGcFDiw2I6
RrUeO4jL/Aj3Yw4dNuW7tYt+O1sRTHgrzxPD9SrOqzz7G0KgoSfdFHe3JVLPN+U1
waK+T0HfLusVJshDaMrMiQFDUiKajb+QKr+bXQhVofH74fjat+oRJ8vjXARSpFk4
/41x5j1Bt/2bHoqtdGPcUizZ4whMwzap+hzVlZgs7BNfepo24PWPRujsN3uopl+8
u4HFpQDlQl7GdqDYDj2zNOHdFQI2UpSf0aIeKCKOpSKF72KDEESpJVQsqO4nxMwE
i2jMujQeCHyTCjBZ+W35RzwT9+0pyZv8FB3c7FYY9FdF/+lvfax5mvFEBd9jO+dp
MQIDAQAB
-----END RSA PUBLIC KEY-----""",
}

# --- OTA Region Configuration ---
OTA_REGION_CONFIG = {
    "cn": {
        "host": "component-ota-cn.allawntech.com",
        "language": "zh-CN",
        "carrier_id": "10010111",
        "public_key_version": "1615879139745",
    },
    "cn_cmcc": {
        "host": "component-ota-cn.allawntech.com",
        "language": "zh-CN",
        "carrier_id": "10011000",
        "public_key_version": "1615879139745",
    },
    "cn_gray": {
        "host": "component-ota-gray.coloros.com",
        "language": "zh-CN",
        "carrier_id": "10010111",
        "public_key_version": "1615879139745",
    },
    "eu": {
        "host": "component-ota-eu.allawnos.com",
        "language": "en-GB",
        "carrier_id": "01000100",
        "public_key_version": "1615897067573",
    },
    "in": {
        "host": "component-ota-in.allawnos.com",
        "language": "en-IN",
        "carrier_id": "00011011",
        "public_key_version": "1615896309308",
    },
    "sg_host": {
        "host": "component-ota-sg.allawnos.com",
        "public_key_version": "1615895993238",
    },
    "sg": {"language": "en-SG", "carrier_id": "01011010"},
    "ru": {"language": "ru-RU", "carrier_id": "00110111"},
    "tr": {"language": "tr-TR", "carrier_id": "01010001"},
    "th": {"language": "th-TH", "carrier_id": "00111001"},
    "gl": {"language": "en-US", "carrier_id": "10100111"},
    "id": {"language": "id-ID", "carrier_id": "00110011"},
    "tw": {"language": "zh-TW", "carrier_id": "00011010"},
    "my": {"language": "ms-MY", "carrier_id": "00111000"},
    "vn": {"language": "vi-VN", "carrier_id": "00111100"},
    "sa": {"language": "sa-SA", "carrier_id": "10000011"},
    "mea": {"language": "en-MEA", "carrier_id": "10100110"},
    "ph": {"language": "en-PH", "carrier_id": "00111110"},
    "roe": {"language": "en-EU", "carrier_id": "10001101"},
    "la": {"language": "en-LA", "carrier_id": "10011010"},
    "br": {"language": "en-BR", "carrier_id": "10011110"},
}

# --- SOTA Configuration ---
SOTA_CONFIG = {
    "api_url_query": "https://component-ota-cn.allawntech.com/update/v6",
    "api_url_update": "https://component-ota-cn.allawntech.com/sotaUpdate/v1",
    "api_url_description": "https://component-ota-cn.allawntech.com/sotaDescriptionInfo/v2",
    "public_key_cn": """-----BEGIN RSA PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApXYGXQpNL7gmMzzvajHa
oZIHQQvBc2cOEhJc7/tsaO4sT0unoQnwQKfNQCuv7qC1Nu32eCLuewe9LSYhDXr9
KSBWjOcCFXVXteLO9WCaAh5hwnUoP/5/Wz0jJwBA+yqs3AaGLA9wJ0+B2lB1vLE4
FZNE7exUfwUc03fJxHG9nCLKjIZlrnAAHjRCd8mpnADwfkCEIPIGhnwq7pdkbamZ
coZfZud1+fPsELviB9u447C6bKnTU4AaMcR9Y2/uI6TJUTcgyCp+ilgU0JxemrSI
PFk3jbCbzamQ6Shkw/jDRzYoXpBRg/2QDkbq+j3ljInu0RHDfOeXf3VBfHSnQ66H
CwIDAQAB
-----END RSA PUBLIC KEY-----""",
    "default_negotiation_version": "1615879139745",
}

# --- Downgrade Configuration ---
DOWNGRADE_CONFIG = {
    "url": "https://downgrade.coloros.com/downgrade/query-v3",
    "url_v2": "https://downgrade.coloros.com/downgrade/query-v2",
    "negotiation_version": 1636449646204,
    "public_key": """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmeQzr0TIbtwZFnDXgatg
6xP9SlNBFho1NTdFQ27SKDF+dBEEfnG9BqRw0na0DUqtpWe2CUtldbU33nnJ0KB6
z7y5f+89o9n8mJxIbh952gpskBxyrhCfpYHV5mt/n9Tkm8OcQWLRFou7/XITuZeZ
ejfUTesQjpfOeCaeKyVSoKQc6WuH7NSYq6B37RMyEn/1+vo8XuHEKD84p29KGpyG
I7ZeL85iOcwBmOD6+e4yideH2RatA1SzEv/9V8BflaFLAWDuPWUjA2WgfOvy5spY
mp/MoMOX4P0d+AkJ9Ms6PUXEUBsbOACmaMFyLCLHmd18+UeGdJR/3I15sXKbJhKe
rwIDAQAB
-----END PUBLIC KEY-----""",
}

# --- IoT Configuration ---
IOT_CONFIG = {
    "old_keys": [
        "oppo1997",
        "baed2017",
        "java7865",
        "231uiedn",
        "09e32ji6",
        "0oiu3jdy",
        "0pej387l",
        "2dkliuyt",
        "20odiuye",
        "87j3id7w",
    ],
    "special_server_cn": "https://iota.coloros.com/post/Query_Update",
    "gauss_auto_url": "https://gauss-otacostauto-cn.allawnfs.com/",
    "gauss_manual_url": "https://gauss-componentotacostmanual-cn.allawnfs.com/",
}

# --- Opex Configuration ---
OPEX_CONFIG = {
    "public_key_cn": """-----BEGIN RSA PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr/B2JwdaZIQqVpx10R4R
o/ZjCLzssu3vIZCKNwDh4LMBkeHRjcjtaVPoPvvTKY74XlMg7fmRv0iQELnlFNtH
jgg8YnmhZObUmpVdpHLhthRSBqpRKl2LhMgYtE/SELUKvzelw2byNcRnU9/PvbsA
Dcgz7IUFAzOvvtxnbaOd9CAthvO+0BTSk3dnBt6CT4nScgr13BAn6RTJI0wV5DZM
pLNsTEXiTcQT3ZX2LcT6bRN8yUmGuARjLh2VG7H1gSxjUUDsKcFmcJY/8zyB64nq
vX4Gya86c2bVaEd+CsMsOEYISWdVrG+Rf6y3BaG1DZRQDh0GD1cwtvA+JtvEmqGk
qwIDAQAB
-----END RSA PUBLIC KEY-----""",
    "cn": {
        "host": "opex-service-cn.allawntech.com",
        "endpoint": "/queryUpdate",
        "public_key_version": "1631001537253",
        "language": "zh-CN",
        "carrier_id": "10010111",
    },
}

# --- Realme EDL Configuration ---
REALME_CONFIG = {
    "gdpr": {"server": "rms01.realme.net", "bucket": "GDPR"},
    "domestic": {"server": "rms11.realme.net", "bucket": "domestic"},
    "export": {"server": "rms01.realme.net", "bucket": "export"},
}
