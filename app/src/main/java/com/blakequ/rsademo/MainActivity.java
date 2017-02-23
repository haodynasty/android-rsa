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

public class MainActivity extends AppCompatActivity implements View.OnClickListener
{
	private Button btn1, btn2,btn_click,btn_click2;// 加密，解密
	private EditText et1, et2, et3;// 需加密的内容，加密后的内容，解密后的内容
	private TextView mTvInfo;
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
		try {
			//自动生成
			mFileEncryptionManager.generateKey();
			publicKey = mFileEncryptionManager.getPublicKey();
			privateKey = mFileEncryptionManager.getPrivateKey();
			//也可以从文件读取
//			InputStream inPublic = getResources().getAssets().open("rsa_public_key.pem");
//			privateKey = FileUtils.readString(inPublic);
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
					// 加密
					byte[] encryptByte = mFileEncryptionManager.encryptByPublicKey(source.getBytes());
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
					// 因为RSA加密后的内容经Base64再加密转换了一下，所以先Base64解密回来再给RSA解密
					byte[] decryptByte = mFileEncryptionManager.decryptByPrivateKey(Base64Utils.decode(encryptContent));
					et3.setText(new String(decryptByte));
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
