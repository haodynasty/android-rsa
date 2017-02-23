package com.blakequ.rsademo;


import android.os.Bundle;
import android.os.Environment;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import com.blakequ.rsa.Base64Utils;
import com.blakequ.rsa.FileEncryptionManager;
import com.blakequ.rsa.FileUtils;
import com.blakequ.rsa.RSAProvider;

import java.io.File;
import java.io.FileInputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Map;

public class MainActivity extends AppCompatActivity implements View.OnClickListener
{
	private Button btn1, btn2,btn_click,btn_click2;// 加密，解密
	private EditText et1, et2, et3;// 需加密的内容，加密后的内容，解密后的内容
	private TextView mTvInfo;
	private static String PUBLICKEY = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCXq6N83mz+K5Jrvp6va7n5BvD466Sxy1kweUbe0O/Nh0wmfTXX68Sz4dUTCIjIiruIan6y5NJZtgwSetamRG5Oc2X2n2oaIVir2m7ciqGw0FGwipp1iH4TX7l3N4gQmgsNl9j76fvhq049zf8e4+s3anXsAvgY6nvFOFRRINHY+wIDAQAB";
	private static String PRIVATEKEY = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAJero3zebP4rkmu+nq9rufkG8PjrpLHLWTB5Rt7Q782HTCZ9NdfrxLPh1RMIiMiKu4hqfrLk0lm2DBJ61qZEbk5zZfafahohWKvabtyKobDQUbCKmnWIfhNfuXc3iBCaCw2X2Pvp++GrTj3N/x7j6zdqdewC+Bjqe8U4VFEg0dj7AgMBAAECgYAzhAT/wLzciAgvuItFoh2EzCrFIaTLDvq4UDkWLXmGIdJnsFe9g0NIpggtctSi6RxRdXqbYMVh20e2byrBRrUAP3KJd+rUJplDk/EHroLVGcIYBX0GDqYuQ/nx2vs7/XuICMKGuT6Mo9QwBOS+Km4+sOX0W0sNtRtW1I8HtgIYQQJBAPVgaU2hBdRn+fmlohKdouEwSjK6qeToPqnj4UJ+Deq55nR7sjqPmB64OcokGoKloYZ+fKmCHr6wLRiOffrHTgMCQQCePKbSfr1XOnTpbWnDkWBcztoidD+dARi43jaJ7zQJWRgADTRjmO7xvAPRkRpg2mNvtmuEV1/hE4qxWNfrvHOpAkEAz5OE4Z/zf5GKPa/p4JesH5YrXqjcaoIx6KSXfhmHCmfDVg0CZFnvVSWB9cf/CUC22UENkpQ6EBSXwathVZHfIwJACXjR95m0lcsfAnYVNaq3HPcY4aUZxbkyFKbgluMlt0WJBT/FGg0miHvbsqi/7npEJ4TA7NwaFiwISlNqIWdXeQJAJAirBot0hMWkxHoaK4Xiw5pQN/5gNDiYUwqYr4pRSno2LIAN6WvIuYwIL94kstK9wx4UMU0xkPxu8rO2p8VpFw==";
	String publicKey, privateKey;
	File saveEncryPath, saveDecryPath;
	FileEncryptionManager mFileEncryptionManager;

	@Override
	protected void onCreate(Bundle savedInstanceState)
	{
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);
		initView();
		mFileEncryptionManager = FileEncryptionManager.getInstance();
		File sdcard = Environment.getExternalStorageDirectory();
		saveEncryPath = new File(sdcard.getPath()+"/diapers_encry.txt");
		saveDecryPath = new File(sdcard.getPath()+"/diapers_decry.txt");
		//1.生成秘钥
		Map<String, Object> keys = null;
		try {
			keys = RSAProvider.generateKeyPair();
			publicKey = RSAProvider.getPublicKeyBytes(keys);
			privateKey = RSAProvider.getPrivateKeyBytes(keys);
			mFileEncryptionManager.generateKey();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private void initView()
	{
		btn1 = (Button) findViewById(R.id.btn1);
		btn2 = (Button) findViewById(R.id.btn2);
		btn1.setOnClickListener(this);
		btn2.setOnClickListener(this);
		btn_click = (Button) findViewById(R.id.btn_click);
		btn_click.setOnClickListener(this);
		btn_click2 = (Button) findViewById(R.id.btn_click2);
		btn_click2.setOnClickListener(this);
		et1 = (EditText) findViewById(R.id.et1);
		et2 = (EditText) findViewById(R.id.et2);
		et3 = (EditText) findViewById(R.id.et3);
		mTvInfo = (TextView) findViewById(R.id.tv_info);
	}

	@Override
	public void onClick(View v)
	{
		switch (v.getId())
		{
			// 加密
			case R.id.btn1:
				String source = et1.getText().toString().trim();
				try
				{
					// 从字符串中得到公钥
					 PublicKey publicKey = RSAUtils.loadPublicKey(PUBLICKEY);
					// 从文件中得到公钥
	//				InputStream inPublic = getResources().getAssets().open("rsa_public_key.pem");
	//				PublicKey publicKey = RSAUtils.loadPublicKey(inPublic);
					// 加密
					byte[] encryptByte = RSAUtils.encryptSimpleData(source.getBytes(), publicKey);
					// 为了方便观察吧加密后的数据用base64加密转一下，要不然看起来是乱码,所以解密是也是要用Base64先转换
					String afterencrypt = Base64Utils.encode(encryptByte);
					et2.setText(afterencrypt);
				} catch (Exception e)
				{
					e.printStackTrace();
				}
				break;
			// 解密
			case R.id.btn2:
				String encryptContent = et2.getText().toString().trim();
				try
				{
					// 从字符串中得到私钥
					 PrivateKey privateKey = RSAUtils.loadPrivateKey(PRIVATEKEY);
					// 从文件中得到私钥
	//				InputStream inPrivate = getResources().getAssets().open("pkcs8_rsa_private_key.pem");
	//				PrivateKey privateKey = RSAUtils.loadPrivateKey(inPrivate);

					// 因为RSA加密后的内容经Base64再加密转换了一下，所以先Base64解密回来再给RSA解密
					byte[] decryptByte = RSAUtils.decryptSimpleData(Base64Utils.decode(encryptContent), privateKey);
					//解密资源文件里的加密资源
	//				byte[] b1 = getBytes();
	//				byte[] decryptByte = RSAUtils.decryptData(b1, privateKey);

					String decryptStr = new String(decryptByte);
					et3.setText(decryptStr);
				} catch (Exception e)
				{
					e.printStackTrace();
				}
				break;
			case R.id.btn_click:
				try {
					//公钥加密
					byte[] data = FileUtils.getBytesFromInputStream(getResources().getAssets().open("test.txt"));
					Log.e("MainActivity", "---------\n加密前数据："+new String(data, "UTF-8"));
					long start=System.currentTimeMillis();
					byte[] result = mFileEncryptionManager.encryptFileByPublicKey(data, saveEncryPath);
					long end=System.currentTimeMillis();
					Log.e("MainActivity","公钥加密耗时 cost time---->"+(end-start));
					Log.e("MainActivity","加密后数据---->\n"+new String(result, "UTF-8"));
				} catch (Exception e) {
					e.printStackTrace();
				}
				break;
			case R.id.btn_click2:
				try {
					//私钥解密
					byte[] data = FileUtils.getBytesFromInputStream(new FileInputStream(saveEncryPath));
					Log.e("MainActivity", "--------------\n解密前数据："+new String(data, "UTF-8"));
					long start=System.currentTimeMillis();
					byte[] result = mFileEncryptionManager.decryptFileByPrivateKey(saveEncryPath, saveDecryPath);
					long end=System.currentTimeMillis();
					Log.e("MainActivity","私钥解密耗时 cost time---->"+(end-start));
					Log.e("MainActivity","解密后数据---->\n"+new String(result, "UTF-8"));
				} catch (Exception e) {
					e.printStackTrace();
				}
				break;
		default:
			break;
		}
	}

	public  void test() {
		try {
			System.err.println("公钥加密——私钥解密");
			String source = "这是一行没有任何意义的文字，你看完了等于没看，不是吗111？";
			System.out.println("\r加密前文字：\r\n" + source);
			byte[] data = source.getBytes();
//			byte[] encodedData = RSAUtils.encryptSimpleData(data, RSAUtils.loadPublicKey(PUBLICKEY));
			byte[] encodedData = RSAProvider.encryptPublicKey(data, publicKey);
			System.out.println("加密后文字：\r\n" + new String(encodedData));
			Log.e("MainActivity","加密前后数据长度 "+data.length+"-->"+encodedData.length);
//			byte[] decodedData = RSAUtils.decryptSimpleData(encodedData, RSAUtils.loadPrivateKey(PRIVATEKEY));
			byte[] decodedData = RSAProvider.decryptPrivateKey(encodedData, privateKey);
			String target = new String(decodedData);
			System.out.println("解密后文字: " + target);
		}catch (Exception e){
			Log.e("System", "test: 解密失败" );
			e.printStackTrace();
		}
	}

}
