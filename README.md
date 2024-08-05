## Steal Core

### هسته ای بر پایه ریلیتی

## ! حتما مطالعه شود !
1- جای x.x.x.x آیپی سرور وارد کنید

2- مقدار secret_key یه متن 10_15 کاراکتری رندوم وارد کنید

3- مقدار interval_second مدت زمانی هست که کلید جدید برای احراز هویت کاربر ساخته میشه پس این عدد رو نه زیاد بالا ببرید و نه زیاد پایین (بین 3 تا 10 خوبه)

4- مقدار skew_second مدت زمان تاخیر ارسال کلید احراز هویت به سرور هست بهتره این عدد از interval_second بیشتر نشه و همچنین این عدد رو بین بازه 1 تا مقداری کمتر از interval_second قرار بدید

5- مقدار sni رو جای سایت مقصد وارد کنید حتما سایت به اضافه پورت وارد بشه (دقیقا مثل چیزی که تو مثال هست)

6- مقدار های read_deadline_second و write_deadline_second مدت زمانی هست که کلاینت یا سرور به درخواست هیچ واکنشی نشون نمیده که اگه مثلا تا 15 ثانیه اتفاقی نیفتاد اتصال رو میبنده ( سیستم فیلترینگ قبلا توی vmess چنین حرکتی رو میزد و اگه سرور اتصال نمیبست شک میکرد که کانکشن vpn  هست)

7-توی users یه لیست از آرایه کاربر ها رو وارد کنید مقدار id مقداری هست که باهاش احراز هویت شکل میگیره و مقدار system_id مقداری هست که باهاش میشه میزان حجمی که یه کاربر خاص رفته رو محاسبه کرد (پس اگه مقدار جفتشون یکی باشه مشکلی پیش نمیاد)

8- حالت tun mode فعلا برای اندروید و ویندوز پشتیبانی میشه که این قابلیت تنها سمت کلاینت کاربرد داره

9- مقدار restapi رو اگه 127.0.0.1:9999 یا هر چیز دیگه ای قرار بدید بعدا میتونید با http request ترافیک کاربر ها رو با system_id محاسبه کنید (یجور api از وضعیت مصرف کاربرا میده)

10- حالت debug_mode هم تنها موقع توسعه هسته کاربرد داره و بهتره تو حالت عادی false باشه که اگر روشن باشه inbound و outbound رو همزمان با هم اجرا میکنه تا تو حالت توسعه کلاینت و سرور همزمان داشته باشیم

### 11- [دانلود کلاینت اندروید و ویندوز](https://github.com/LuckyLuke-a/StealClient)



***


### کانفیگ کلاینت :
```
{
    "inbounds": [
        {
            "addr": "127.0.0.1:1080",
            "protocol": "socks5"
        },
		        {
            "addr": "127.0.0.1:1081",
            "protocol": "http"
        }
    ],
    "outbounds": [
        {
            "addr": "x.x.x.x:443",
            "protocol": "reality",
            "protocol_settings":{
                "secret_key": "randomSecretKey",
                "interval_second": 7,
                "skew_second": 3,
                "sni": "fast.com:443",
                "read_deadline_second": 15,
                "write_deadline_second": 15
            },
            "users":[
                {
                    "id":"TestUser",
                    "system_id":"TestUser" 
                }
            ]
        }
    ],
    "logging": true,
    "tun": {
        "start": false,
        "name": "stealClient",
        "mtu": 0
    },
    "restapi":"",
    "debug_mode": false
}
```

### کانفیگ سرور :
```
{
    "inbounds": [
        {
            "addr": ":443",
            "protocol": "reality",
            "protocol_settings":{
                "secret_key": "randomSecretKey",
                "interval_second": 7,
                "skew_second": 3,
                "sni": "fast.com:443",
                "read_deadline_second": 15,
                "write_deadline_second": 15
            },
            "users":[
                {
                    "id":"TestUser",
                    "system_id":"TestUser" 
                }
            ]
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
        }
    ],
    "logging": true,
    "restapi":"",
    "debug_mode": false
}
```


