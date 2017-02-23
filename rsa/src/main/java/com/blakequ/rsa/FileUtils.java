package com.blakequ.rsa;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

/**
 * Copyright (C) BlakeQu All Rights Reserved <blakequ@gmail.com>
 * <p>
 * Licensed under the blakequ.com License, Version 1.0 (the "License");
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * <p>
 * author  : quhao <blakequ@gmail.com> <br>
 * date     : 2017/2/22 21:08 <br>
 * last modify author : <br>
 * version : 1.0 <br>
 * description:
 */

public class FileUtils {

    /**
     * 注意保持加密内容的时候不能先将byte数组转换为string，因为转换为string的时候，后面会默认加上结束符，造成解密失败，故而在读取和写入都使用byte数组
     * @param data
     * @param filePath
     */
    public static boolean saveDataToFile(byte[] data, File filePath){
        if (data == null || filePath == null){
            throw  new IllegalArgumentException("Input data is null or output path is null");
        }
        boolean result = false;
        try {
            result = write(filePath, data, false);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }

    /**
     * 从文件读取byte数组
     * @param sourceFile
     * @return
     * @throws FileNotFoundException
     */
    public static byte[] getDataFromFile(File sourceFile) throws FileNotFoundException {
        return getBytesFromInputStream(new FileInputStream(sourceFile));
    }

    /**
     * 从输入流中读取byte数组
     * String filePath
     */
    public static byte[] getBytesFromInputStream(InputStream inputStream){
        byte[] buffer = null;
        ByteArrayOutputStream bos = new ByteArrayOutputStream(1000);
        byte[] b = new byte[1000];
        try {
            int n;
            while ((n = inputStream.read(b)) != -1) {
                bos.write(b, 0, n);
            }
            buffer = bos.toByteArray();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                inputStream.close();
                bos.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return buffer;
    }


    /**
     * 读取密钥信息
     *
     * @param in
     * @return
     * @throws IOException
     */
    public static String readString(InputStream in) throws IOException {
        BufferedReader br = new BufferedReader(new InputStreamReader(in));
        String readLine = null;
        StringBuilder sb = new StringBuilder();
        while ((readLine = br.readLine()) != null) {
            if (readLine.charAt(0) == '-') {
                continue;
            } else {
                sb.append(readLine);
                sb.append('\r');
            }
        }

        return sb.toString();
    }

    /**
     * 将内容写文件
     * @param file
     * @param content
     * @param append
     * @return
     */
    private static boolean write(File file, byte[] content, boolean append) {
        if(file != null && content != null) {
            if(!file.exists()) {
                file = createNewFile(file);
            }

            FileOutputStream ops = null;

            try {
                ops = new FileOutputStream(file, append);
                ops.write(content);
                return true;
            } catch (Exception var15) {
                var15.printStackTrace();
            } finally {
                try {
                    ops.close();
                } catch (IOException var14) {
                    var14.printStackTrace();
                }
                ops = null;
            }

            return false;
        }
        return false;
    }

    /**
     * 创建新文件
     * @param file
     * @return
     */
    private static File createNewFile(File file) {
        try {
            if(file.exists()) {
                return file;
            } else {
                File e = file.getParentFile();
                if(!e.exists()) {
                    e.mkdirs();
                }

                if(!file.exists()) {
                    file.createNewFile();
                }

                return file;
            }
        } catch (IOException var2) {
            var2.printStackTrace();
            return null;
        }
    }
}
