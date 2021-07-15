package com.wuhan.chaindemo;

import com.alipay.mychain.sdk.api.MychainClient;
import com.alipay.mychain.sdk.api.callback.IAsyncCallback;
import com.alipay.mychain.sdk.api.env.ClientEnv;
import com.alipay.mychain.sdk.api.env.ISslOption;
import com.alipay.mychain.sdk.api.env.SignerOption;
import com.alipay.mychain.sdk.api.env.SslBytesOption;
import com.alipay.mychain.sdk.api.logging.AbstractLoggerFactory;
import com.alipay.mychain.sdk.api.logging.ILogger;
import com.alipay.mychain.sdk.api.utils.Utils;
import com.alipay.mychain.sdk.crypto.MyCrypto;
import com.alipay.mychain.sdk.crypto.PublicKey;
import com.alipay.mychain.sdk.crypto.keyoperator.Pkcs8KeyOperator;
import com.alipay.mychain.sdk.crypto.keypair.Keypair;
import com.alipay.mychain.sdk.crypto.signer.SignerBase;
import com.alipay.mychain.sdk.domain.account.Account;
import com.alipay.mychain.sdk.domain.account.AccountStatus;
import com.alipay.mychain.sdk.domain.account.AuthMap;
import com.alipay.mychain.sdk.domain.account.Identity;
import com.alipay.mychain.sdk.errorcode.ErrorCode;
import com.alipay.mychain.sdk.message.Response;
import com.alipay.mychain.sdk.message.transaction.AbstractTransactionRequest;
import com.alipay.mychain.sdk.message.transaction.account.*;
import com.alipay.mychain.sdk.type.BaseFixedSizeUnsignedInteger;
import com.alipay.mychain.sdk.utils.IOUtil;
import com.alipay.mychain.sdk.utils.RandomUtil;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;

/**
 * @author Chris
 * @date 2021/7/14 9:29
 * @Email:gem7991@dingtalk.com
 */
public class AccountDemo {
    private static final String account = "chrisblocktest";
    private static Identity userIdentity;
    private static Keypair userKeypair;

    /**
     * create account test
     */
    private static Identity testAccount1 = Utils.getIdentityByName("test_account_" + System.currentTimeMillis());
    /**
     * sdk client
     */
    private static MychainClient sdk;
    /**
     * client key password
     */
    private static String keyPassword = "Local#123";
    /**
     * user password
     */
    private static String userPassword = "Local#123";
    /**
     * host ip
     */

    private static String host = "47.103.163.48";

    /**
     * server port
     */
    private static int port = 18130;
    /**
     * trustCa password.
     */
    private static String trustStorePassword = "mychain";
    /**
     * mychain environment
     */
    private static ClientEnv env;
    /**
     * mychain is tee Chain
     */
    private static boolean isTeeChain = false;
    /**
     * tee chain publicKeys
     */
    private static List<byte[]> publicKeys = new ArrayList<byte[]>();
    /**
     * tee chain secretKey
     */
    private static String secretKey = "123456";


    private static void initMychainEnv() throws IOException {
        // any user key for sign message
        String userPrivateKeyFile = "user.key";
        userIdentity = Utils.getIdentityByName(account);
        Pkcs8KeyOperator pkcs8KeyOperator = new Pkcs8KeyOperator();
        userKeypair = pkcs8KeyOperator.load(IOUtil.inputStreamToByte(AccountDemo.class.getClassLoader().getResourceAsStream(userPrivateKeyFile)), userPassword);

        // use publicKeys by tee
        if (isTeeChain) {
            Keypair keypair = new Pkcs8KeyOperator()
                    .loadPubkey(
                            IOUtil.inputStreamToByte(AccountDemo.class.getClassLoader().getResourceAsStream("test_seal_pubkey.pem")));
            byte[] publicKeyDer = keypair.getPubkeyEncoded();
            publicKeys.add(publicKeyDer);
        }

        env = buildMychainEnv();
        ILogger logger = AbstractLoggerFactory.getInstance(AccountDemo.class);
        env.setLogger(logger);
    }

    private static ClientEnv buildMychainEnv() throws IOException {
        InetSocketAddress inetSocketAddress = InetSocketAddress.createUnresolved(host, port);
        String keyFilePath = "client.key";
        String certFilePath = "client.crt";
        String trustStoreFilePath = "trustCa";
        // build ssl option
        ISslOption sslOption = new SslBytesOption.Builder()
                .keyBytes(IOUtil.inputStreamToByte(AccountDemo.class.getClassLoader().getResourceAsStream(keyFilePath)))
                .certBytes(IOUtil.inputStreamToByte(AccountDemo.class.getClassLoader().getResourceAsStream(certFilePath)))
                .keyPassword(keyPassword)
                .trustStorePassword(trustStorePassword)
                .trustStoreBytes(
                        IOUtil.inputStreamToByte(AccountDemo.class.getClassLoader().getResourceAsStream(trustStoreFilePath)))
                .build();

        List<InetSocketAddress> socketAddressArrayList = new ArrayList<InetSocketAddress>();
        socketAddressArrayList.add(inetSocketAddress);

        List<SignerBase> signerBaseList = new ArrayList<SignerBase>();
        SignerBase signerBase = MyCrypto.getInstance().createSigner(userKeypair);
        signerBaseList.add(signerBase);
        SignerOption signerOption = new SignerOption();
        signerOption.setSigners(signerBaseList);
        return ClientEnv.build(socketAddressArrayList, sslOption, signerOption);
    }

    private static void initSdk() {
        sdk = new MychainClient();
        boolean initResult = sdk.init(env);
        if (!initResult) {
            exit("initSdk", "sdk init failed.");
        }else{
            System.out.println("sdk init success");
        }
    }

    private static String getErrorMsg(int errorCode) {
        int minMychainSdkErrorCode = ErrorCode.SDK_INTERNAL_ERROR.getErrorCode();
        if (errorCode < minMychainSdkErrorCode) {
            return ErrorCode.valueOf(errorCode).getErrorDesc();
        } else {
            return ErrorCode.valueOf(errorCode).getErrorDesc();
        }
    }

    private static void exit(String tag, String msg) {
        exit(String.format("%s error : %s ", tag, msg));
    }

    private static void exit(String msg) {
        System.out.println(msg);
        System.exit(0);
    }

    private static void signRequest(AbstractTransactionRequest request) {
        // sign request
        long ts = sdk.getNetwork().getSystemTimestamp();
        request.setTxTimeNonce(ts, BaseFixedSizeUnsignedInteger.Fixed64BitUnsignedInteger
                .valueOf(RandomUtil.randomize(ts + request.getTransaction().hashCode())), true);
        request.complete();
        sdk.getConfidentialService().signRequest(env.getSignerOption().getSigners(), request);
    }

    //CreateAccount
    private static  void createAccount(){
        long startIndex = System.currentTimeMillis();
        String newAccountname = "wudaaccount_" + startIndex;
        Pkcs8KeyOperator pkcs8KeyOperator = new Pkcs8KeyOperator();
        InputStream userPrivateKeyFilePath = AccountDemo.class.getClassLoader().getResourceAsStream(
                "user.key");
        Keypair userKeypair= null;
        try {
            userKeypair = pkcs8KeyOperator.load(IOUtil.inputStreamToByte(userPrivateKeyFilePath), userPassword);
        } catch (IOException e) {
            e.printStackTrace();
        }
        // build account
        Account newAccount = new Account();
        newAccount.setIdentity(Utils.getIdentityByName(newAccountname));
        newAccount.setBalance(0);
        newAccount.setStatus(AccountStatus.NORMAL);
        AuthMap authMap = new AuthMap();
        newAccount.setAuthMap(authMap.updateAuth(new PublicKey(userKeypair), 105));
        newAccount.setRecoverKey(new PublicKey(userKeypair));
        CreateAccountRequest request = new CreateAccountRequest(userIdentity, newAccount);
        // create testAccount
        CreateAccountResponse createAccountResult = sdk.getAccountService().createAccount(request);
        if (!createAccountResult.isSuccess()) {
            exit("wudaaccount", getErrorMsg((int)createAccountResult.getTransactionReceipt().getResult()));
        } else {
            System.out.println(String.format("create %s success.AntChain response data:%s",newAccountname,createAccountResult.toString()));
        }
    }

    //Async CreateAccount
    private static  void  asyncCreateAccount(){
        long startIndex = System.currentTimeMillis();
        final String newAccountName = "wudaaccount_" + startIndex;
        Pkcs8KeyOperator pkcs8KeyOperator = new Pkcs8KeyOperator();
        InputStream userPrivateKeyFilePath = AccountDemo.class.getClassLoader().getResourceAsStream(
                "user.key");
        Keypair userKeypair= null;
        try {
            userKeypair = pkcs8KeyOperator.load(IOUtil.inputStreamToByte(userPrivateKeyFilePath), userPassword);
        } catch (IOException e) {
            e.printStackTrace();
        }
        // build account
        Account newAccount = new Account();
        newAccount.setIdentity(Utils.getIdentityByName(newAccountName));
        newAccount.setBalance(0);
        newAccount.setStatus(AccountStatus.NORMAL);
        AuthMap authMap = new AuthMap();
        newAccount.setAuthMap(authMap.updateAuth(new PublicKey(userKeypair), 100));
        newAccount.setRecoverKey(new PublicKey(userKeypair));
        CreateAccountRequest request = new CreateAccountRequest(userIdentity, newAccount);
        int result = sdk.getAccountService().asyncCreateAccount(
                request,
                new IAsyncCallback() {
                    @Override
                    public void onResponse(int errorCode, Response response) {
                        // 参考错误信息说明文档，检查返回的数据
                        CreateAccountResponse createAccountResponse = (CreateAccountResponse)response ;
                        if(!response.isSuccess()){
                            System.out.println("async create account failed, errorCode:" + errorCode + ", response: " + response.getErrorCode());
                        } else {
                            System.out.println(String.format("async create %s success.AntChain response data:%s",newAccountName,createAccountResponse.toString()));
                        }
                    }
                });
    }


    //冻结账户
    private static  void freezeAccount(){
        Identity toIdentity = Utils.getIdentityByName("wudaaccount_1626226539389");
        FreezeAccountRequest request = new FreezeAccountRequest(userIdentity, toIdentity);
        FreezeAccountResponse result = sdk.getAccountService().freezeAccount(request);
        if (!result.isSuccess()) {
            exit("freezeAccount", getErrorMsg((int)result.getTransactionReceipt().getResult()));
        } else {
            System.out.println(String.format("freeze %s success.AntChain response data:%s",toIdentity.toString(),result.toString()));
        }
    }

    private static void setRecoverKey() throws IOException {
        SetRecoverKeyRequest request = new SetRecoverKeyRequest(
                Utils.getIdentityByName("wudaaccount_1626226539389"), new PublicKey(userKeypair));
        SetRecoverKeyResponse response = sdk.getAccountService().setRecoverKey(request);
        System.out.println("交易哈希为： " + response.getTxHash() + "\n"+ "交易结果: "+response.getErrorCode());
    }

    public static void main(String[] args) throws Exception {
        //step 1:init mychain env.
        initMychainEnv();
        //step 2: init sdk client
        initSdk();

        //账户操作
        createAccount();

        System.in.read();
        //step 6 : sdk shut down
        sdk.shutDown();
    }
}
