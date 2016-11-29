//
//  ViewController.m
//  XIBTest
//
//  Created by 曹帅 on 16/11/24.
//  Copyright © 2016年 北京浩鹏盛世科技有限公司. All rights reserved.
//

#import "ViewController.h"
#import<CommonCrypto/CommonDigest.h>
#import "MyRequest.h"
#import "WDCrypto.h"
#import "AFNetworking.h"
@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
}

#pragma mark - 32位 大写
- (NSString *)MD5ForUpper32Bate:(NSString *)str{
    
    //要进行UTF8的转码
    const char* input = [str UTF8String];
    unsigned char result[CC_MD5_DIGEST_LENGTH];
    CC_MD5(input, (CC_LONG)strlen(input), result);
    
    NSMutableString *digest = [NSMutableString stringWithCapacity:CC_MD5_DIGEST_LENGTH * 2];
    for (NSInteger i = 0; i < CC_MD5_DIGEST_LENGTH; i++) {
        [digest appendFormat:@"%02X", result[i]];
    }
    
    return digest;
}
- (NSString *)HMACMD5WithString:(NSString *)toEncryptStr WithKey:(NSString *)keyStr
{
    const char *cKey  = [keyStr cStringUsingEncoding:NSUTF8StringEncoding];
    const char *cData = [toEncryptStr cStringUsingEncoding:NSUTF8StringEncoding];
    const unsigned int blockSize = 64;
    char ipad[blockSize];
    char opad[blockSize];
    char keypad[blockSize];
    
    unsigned int keyLen = strlen(cKey);
    CC_MD5_CTX ctxt;
    if (keyLen > blockSize) {
        CC_MD5_Init(&ctxt);
        CC_MD5_Update(&ctxt, cKey, keyLen);
        CC_MD5_Final((unsigned char *)keypad, &ctxt);
        keyLen = CC_MD5_DIGEST_LENGTH;
    }
    else {
        memcpy(keypad, cKey, keyLen);
    }
    
    memset(ipad, 0x36, blockSize);
    memset(opad, 0x5c, blockSize);
    
    int i;
    for (i = 0; i < keyLen; i++) {
        ipad[i] ^= keypad[i];
        opad[i] ^= keypad[i];
    }
    
    CC_MD5_Init(&ctxt);
    CC_MD5_Update(&ctxt, ipad, blockSize);
    CC_MD5_Update(&ctxt, cData, strlen(cData));
    unsigned char md5[CC_MD5_DIGEST_LENGTH];
    CC_MD5_Final(md5, &ctxt);
    
    CC_MD5_Init(&ctxt);
    CC_MD5_Update(&ctxt, opad, blockSize);
    CC_MD5_Update(&ctxt, md5, CC_MD5_DIGEST_LENGTH);
    CC_MD5_Final(md5, &ctxt);
    
    const unsigned int hex_len = CC_MD5_DIGEST_LENGTH*2+2;
    char hex[hex_len];
    for(i = 0; i < CC_MD5_DIGEST_LENGTH; i++) {
        snprintf(&hex[i*2], hex_len-i*2, "%02x", md5[i]);
    }
    
    NSData *HMAC = [[NSData alloc] initWithBytes:hex length:strlen(hex)];
    NSString *hash = [[NSString alloc] initWithData:HMAC encoding:NSUTF8StringEncoding];

    return hash;
}
- (NSString*)dictionaryToJson:(NSDictionary *)dic{
    NSError *parseError = nil;
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:dic options:NSJSONWritingPrettyPrinted error:&parseError];
    return [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
}
- (IBAction)loginAction:(id)sender {
    
    NSMutableDictionary *dic = [NSMutableDictionary dictionary];
    NSDate *currentDate = [NSDate date];//获取当前时间，日期
    NSDateFormatter *dateFormatter = [[NSDateFormatter alloc] init];
    [dateFormatter setDateFormat:@"yyyyMMddHHmmss"];
    NSString *dateString = [dateFormatter stringFromDate:currentDate];
    [dic setObject:@"1.0" forKey:@"appVer"];
    [dic setObject:@"7.0" forKey:@"osVer"];
    [dic setObject:@"0" forKey:@"termType"];
    [dic setObject:dateString forKey:@"resTm"];
    [dic setObject:@"1.0" forKey:@"version"];
    [dic setObject:@"6f7b28b75aee4fafb4a88d86f106ee84" forKey:@"sessionId"];
    NSArray *strings = [dic allValues];
    NSString *string = [strings componentsJoinedByString:@""];
    NSString *hmac = [self HMACMD5WithString:string WithKey:@"6f7b28b75aee4fafb4a88d86f106ee84"];
    [dic setObject:hmac forKey:@"hmac"];
    [dic setObject:self.userText.text forKey:@"username"];

    NSData *date  = [self.passText.text dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *app =  [WDCrypto encryptWithDESAndRSA:date withKey:@"1234qwer" keyPath:nil];
    [dic setObject:[app objectForKey:@"data"] forKey:@"password"];
    
    NSString *json = [self dictionaryToJson:dic];
    NSDictionary *dicss = @{@"message":json};
    NSLog(@"%@                                 %@",dic,dicss);
    [MyRequest POST:@"http://120.26.104.106/user/login.jhtml" withParameters:dicss CacheTime:20 isLoadingView:@"正在加载..." success:^(id responseObject, BOOL succe, NSDictionary *jsonDic) {
       NSLog(@"%@",jsonDic);
    } failure:^(NSError *error) {
        NSLog(@"%@",error);
    }];
//    [self postDic:dicss withUrl:@"http://120.26.104.106/user/login.jhtml"];
//}
//
//- (AFHTTPSessionManager *)ManagerSetHearderandToken{
//    
//    AFHTTPSessionManager *manager = [AFHTTPSessionManager manager];
//    manager.requestSerializer = [AFHTTPRequestSerializer serializer];
//    [UIApplication sharedApplication].networkActivityIndicatorVisible = YES;
//    ((AFJSONResponseSerializer *)manager.responseSerializer).removesKeysWithNullValues = YES;
//    manager.responseSerializer.acceptableContentTypes = [NSSet setWithObjects:@"application/json", @"text/json", @"text/javascript",@"text/html", nil];
//    return manager;
//}
//# pragma 单拎出来的POST方法
//- (void)postDic:(NSDictionary *)dic withUrl:(NSString *)url{
//    AFHTTPSessionManager *manager = [self ManagerSetHearderandToken];
//    manager.requestSerializer.timeoutInterval = 10;
//    [manager POST:url parameters:dic progress:^(NSProgress * _Nonnull downloadProgress) {
//        
//    } success:^(NSURLSessionDataTask * _Nonnull task, id  _Nullable responseObject) {
//        NSLog(@"%@",responseObject);
//    } failure:^(NSURLSessionDataTask * _Nullable task, NSError * _Nonnull error) {
//       
//    }];
//}
//# pragma 单拎出来的GET方法
//- (void)getData:(NSString *)url{
//    AFHTTPSessionManager *manager = [self ManagerSetHearderandToken];
//    manager.requestSerializer.timeoutInterval = 10;
//    NSString *baseUrl = @"";
//    [manager GET:baseUrl parameters:nil progress:^(NSProgress * _Nonnull downloadProgress) {
//        
//    } success:^(NSURLSessionDataTask * _Nonnull task, id  _Nullable responseObject) {
//       
//    } failure:^(NSURLSessionDataTask * _Nullable task, NSError * _Nonnull error) {
//      
//    }];
//    
//}
//- (void)netWorkingDone{
//    [UIApplication sharedApplication].networkActivityIndicatorVisible = NO;
}












- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}


@end
