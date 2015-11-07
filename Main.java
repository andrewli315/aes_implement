package aes;
import java.io.* ;
import java.util.*;

public class Main{
	
	public static void main(String[] args) throws Exception{
		long beginTime = System.nanoTime();
		String route_en,route_de,route_en_in,route_de_in;
		File enc = new File(args[4]);
		enc.mkdir();
			
		File dec = new File(args[5]);
		dec.mkdir();
		
		File enc_file = new File(args[3]);
		if(!enc_file.exists())
		{
			System.out.println("cannot find the directory!");
			System.exit(1);
		}
		File[] file_read = enc_file.listFiles();
	
		String file_name[] = enc_file.list();
		if(args[2].compareTo("ECB")==0)
		{
			for(int i=0;i <file_name.length ;i++){
				if(file_read[i].isDirectory()){
					continue;
				}
				else{
					route_en = new String(args[4]+File.separator+file_name[i]);//the route of encrypted data output file
					route_de = new String(args[5]+File.separator+file_name[i]);//the route of decrypted data output file
					route_en_in = new String(args[3]+File.separator+file_name[i]);//the route of plaintext input file
					route_de_in = new String(args[4]+File.separator+file_name[i]);//the route of encrypted-data input file
					ECB_encrypt(route_en_in,route_en,args[0]);
					ECB_decrypt(route_de_in,route_de,args[0]);
				}
			}
		}
		else if(args[2].compareTo("CBC")==0)
		{
			for(int i=0;i <file_name.length ;i++){
				if(file_read[i].isDirectory()){
					continue;
				}
				else{
					route_en = new String(args[4]+File.separator+file_name[i]);//the route of encrypted data output file
					route_de = new String(args[5]+File.separator+file_name[i]);//the route of decrypted data output file
					route_en_in = new String(args[3]+File.separator+file_name[i]);//the route of plaintext input file
					route_de_in = new String(args[4]+File.separator+file_name[i]);//the route of encrypted-data input file
					CBC_encrypt(args[1],route_en_in,route_en,args[0]);
					CBC_decrypt(args[1],route_de_in,route_de,args[0]);
				}
			}
		}
		else if(args[2].compareTo("CFB")==0)
		{
			for(int i=0;i <file_name.length ;i++){
				if(file_read[i].isDirectory()){
					continue;
				}
				else{
					route_en = new String(args[4]+File.separator+file_name[i]);//the route of encrypted data output file
					route_de = new String(args[5]+File.separator+file_name[i]);//the route of decrypted data output file
					route_en_in = new String(args[3]+File.separator+file_name[i]);//the route of plaintext input file
					route_de_in = new String(args[4]+File.separator+file_name[i]);//the route of encrypted-data input file
					CFB_encrypt(args[1],route_en_in,route_en,args[0]);
					CFB_decrypt(args[1],route_de_in,route_de,args[0]);
				}
			}
		}
		else if(args[2].compareTo("OFB")==0)
		{
			for(int i=0;i <file_name.length ;i++){
				if(file_read[i].isDirectory()){
					continue;
				}
				else{
					route_en = new String(args[4]+File.separator+file_name[i]);//the route of encrypted data output file
					route_de = new String(args[5]+File.separator+file_name[i]);//the route of decrypted data output file
					route_en_in = new String(args[3]+File.separator+file_name[i]);//the route of plaintext input file
					route_de_in = new String(args[4]+File.separator+file_name[i]);//the route of encrypted-data input file
					OFB_encrypt(args[1],route_en_in,route_en,args[0]);
					OFB_decrypt(args[1],route_de_in,route_de,args[0]);
				}
			}
		}
		else if(args[2].compareTo("CTR")==0)
		{
			for(int i=0;i <file_name.length ;i++){
				if(file_read[i].isDirectory()){
					continue;
				}
				else{
					route_en = new String(args[4]+File.separator+file_name[i]);//the route of encrypted data output file
					route_de = new String(args[5]+File.separator+file_name[i]);//the route of decrypted data output file
					route_en_in = new String(args[3]+File.separator+file_name[i]);//the route of plaintext input file
					route_de_in = new String(args[4]+File.separator+file_name[i]);//the route of encrypted-data input file
					CTR_encrypt(args[1],route_en_in,route_en,args[0]);
					CTR_decrypt(args[1],route_de_in,route_de,args[0]);
				}
			}
		}
		else{
			System.out.println("there is no such valid mode!");
		}
		long endTime = System.nanoTime();
        System.out.println("Program cost time:\t" + (double) (endTime - beginTime) / 1000000 + " ms");
	}
	public static void CBC_encrypt(String IV,String file_in,String file_out,String key)throws Exception{
		File fin = new File(file_in);//use File class to find out the file;
		DataInputStream input = new DataInputStream(new BufferedInputStream (new FileInputStream(fin)));
		File fout = new File(file_out);
		DataOutputStream output = new DataOutputStream(new BufferedOutputStream(new FileOutputStream(fout)));
		int index=0;//the index of byte[] in order to get the data of plaintext;
		int temp =0;
		int cbc_iv,cbc_txt;
		byte b[] = new byte[16];
		byte[] iv = IV.getBytes();	
		AES aes = new AES(key.getBytes());//set key
        while(( temp = input.read()) != -1){// if the size of array is 16*8,then call encrypt  function	
			b[index] = (byte)temp;
			if(index == 15){
				index =0;
				for(int i=0;i<16;i++ )
				{
					cbc_iv = iv[i] & 0xFF;
					cbc_txt = b[i] & 0xFF;
					b[i] = (byte) (cbc_iv ^ cbc_txt);
				}
				byte[] ciphertext = aes.encrypt(b);
				for(int i=0;i<16;i++)
					iv[i] = ciphertext[i];
				output.write(ciphertext);//write the bitStream to output file
				for(int i =0;i<16;i++)	
					b[i] = 0;
			}	
			else
				index++;
		}
		if(index < 15 && index !=0){
			for(int i =index;i<16;i++)
				b[i] = (byte)(16-index);//using PKCS7 padding 
			for(int i=0;i<16;i++ )
			{
					cbc_iv = iv[i] & 0xFF;
					cbc_txt = b[i] & 0xFF;
					b[i] = (byte) (cbc_iv ^ cbc_txt);
			}
			byte[] ciphertext = aes.encrypt(b);
			output.write(ciphertext);
		}
		else if(b[15]!= -1 && temp == -1 && index == 0)
		{
			for(int i=0;i<16;i++)
			{
				b[i] = (byte)16;
			}
			for(int i=0;i<16;i++ )
			{					
					cbc_iv = iv[i] & 0xFF;
					cbc_txt = b[i] & 0xFF;
					b[i] = (byte) (cbc_iv ^ cbc_txt);
			}
			byte[] ciphertext = aes.encrypt(b);
			output.write(ciphertext);
			
		}
		output.flush();
		output.close();	
		input.close();
	}
	public static void CBC_decrypt(String IV,String file_in,String file_out,String key)throws Exception{
		File fin = new File(file_in);
		DataInputStream input = new DataInputStream(new BufferedInputStream (new FileInputStream(fin)));
		File fout= new File(file_out);
		DataOutputStream out = new DataOutputStream(new BufferedOutputStream(new FileOutputStream(fout)));
		AES aes = new AES(key.getBytes());//set key
		byte get[] = new byte[16];//get the binary input data 
		byte[] iv = IV.getBytes();
		int cbc_iv,cbc_txt;
		int counter=0;
		int count =0;
		int temp=0;
		int index=0;
		while(true){
			if(counter ==0)
			{
					temp = input.read();
					counter++;
			}
			get[0] = (byte)temp;
			for(int i=1;i<16;i++)
			{
				temp =input.read();
				get[i] = (byte)temp;
			}
			temp = input.read();
			if(temp != -1)
			{
				
				byte[] decrypt = aes.decrypt(get);
				for(int i=0;i<16;i++)
				{
					cbc_iv = iv[i] & 0xFF;
					cbc_txt = decrypt[i] & 0xFF;
					decrypt[i] = (byte) (cbc_iv ^ cbc_txt);
					iv[i] = get[i];
				}
				out.write(decrypt);
				get[0] = (byte)temp;
				
			}
			else if(temp == -1){
				System.out.printf("%d\n",temp);
				byte[] decrypt = aes.decrypt(get);
				for(int i =0;i<16;i++)
				{
					cbc_iv = iv[i] & 0xFF;
					cbc_txt = decrypt[i] & 0xFF;
					decrypt[i] = (byte) (cbc_iv ^ cbc_txt);
				}
				
				
				for(int i =0;i<16;i++)//delete the padding character in encryption process
				{
					if(decrypt[i] == decrypt[15])
						count++;
				}
				//out.write(decrypt);
				System.out.println((decrypt[15])+" "+count);
				if((decrypt[15]) == count)
				{
					out.write(decrypt,0,16-count);
				}
				else{
					out.write(decrypt);
				}
				break;
			}
			
		}
		out.flush();
		out.close();
		input.close();
	}
	public static void ECB_encrypt(String file_in,String file_out,String key)throws Exception{
		File fin = new File(file_in);//use File class to find out the file;
		DataInputStream input = new DataInputStream(new BufferedInputStream (new FileInputStream(fin)));
		File fout = new File(file_out);
		DataOutputStream output = new DataOutputStream(new BufferedOutputStream(new FileOutputStream(fout)));
		int index=0;//the index of byte[] in order to get the data of plaintext;
		int temp =0;
		byte b[] = new byte[16];
		AES aes = new AES(key.getBytes());//set key
        while(( temp = input.read()) != -1){// if the size of array is 16*8,then call encrypt  function	
			b[index] = (byte)temp;
			if(index == 15){
				index =0;
				byte[] ciphertext = aes.encrypt(b);
				output.write(ciphertext);//write the bitStream to output file
				for(int i =0;i<16;i++)	
					b[i] = 0;
			}	
			else
				index++;
		}
		if(index < 15 && index !=0){
			for(int i =index;i<16;i++)
				b[i] = (byte)(16-index);//using PKCS7 padding 
			byte[] ciphertext = aes.encrypt(b);
			output.write(ciphertext);
		}
		else if(b[15]!= -1 && temp == -1 && index == 0)
		{
			for(int i=0;i<16;i++)
			{
				b[i] = (byte)16;
			}
			byte[] ciphertext = aes.encrypt(b);
			output.write(ciphertext);
			
		}
		output.flush();
		output.close();	
		input.close();
	}
	public static void ECB_decrypt(String file_in,String file_out,String key)throws Exception{
		File fin = new File(file_in);
		DataInputStream input = new DataInputStream(new BufferedInputStream (new FileInputStream(fin)));
		File fout= new File(file_out);
		DataOutputStream out = new DataOutputStream(new BufferedOutputStream(new FileOutputStream(fout)));
		AES aes = new AES(key.getBytes());//set key
		byte get[] = new byte[16];//get the binary input data 
		int pad;
		int counter=0;
		int count =0;
		int temp=0;
		int index=0;
		while(true){
			if(counter ==0)
			{
					temp = input.read();
					counter++;
			}
			get[0] = (byte)temp;
			for(int i=1;i<16;i++)
			{
				temp =input.read();
				get[i] = (byte)temp;
			}
			temp = input.read();
			if(temp != -1)
			{
				
				byte[] decrypt = aes.decrypt(get);
				System.out.printf("%d ",temp);
				out.write(decrypt);
				get[0] = (byte)temp;
				
			}
			else if(temp == -1){
				System.out.printf("%d\n",temp);
				byte[] decrypt = aes.decrypt(get);
				for(int i =0;i<16;i++)//delete the padding character in encryption process
				{
					if(decrypt[i] == decrypt[15])
						count++;
				}
				//out.write(decrypt);
				System.out.println((decrypt[15])+" "+count);
				if((decrypt[15]) == count)
					out.write(decrypt,0,16-count);
				else
					out.write(decrypt);
				break;
			}
			
		}
		out.flush();
		out.close();
		input.close();
	}
	public static void CFB_encrypt(String IV,String file_in,String file_out,String key)throws Exception{
		File fin = new File(file_in);//use File class to find out the file;
		DataInputStream input = new DataInputStream(new BufferedInputStream (new FileInputStream(fin)));
		File fout = new File(file_out);
		DataOutputStream output = new DataOutputStream(new BufferedOutputStream(new FileOutputStream(fout)));
		int index=0;//the index of byte[] in order to get the data of plaintext;
		int temp =0;
		int cfb_iv,cfb_txt;
		byte b[] = new byte[16];
		byte ciphertext[] = new byte[16];	
		AES aes = new AES(key.getBytes());//set key
        byte[] iv = aes.encrypt(IV.getBytes());
		
		while(( temp = input.read()) != -1){// if the size of array is 16*8,then call encrypt  function	
			cfb_iv = iv[index] & 0xFF;
			cfb_txt = temp & 0xFF;
			ciphertext[index] = (byte) (cfb_iv ^ cfb_txt);
			output.write(ciphertext[index]);
			index++;
			if(index == 16){
				iv = aes.encrypt(ciphertext);
				index=0;
			}
		}
		output.flush();
		output.close();	
		input.close();
	}
	public static void CFB_decrypt(String IV,String file_in,String file_out,String key)throws Exception{
		File fin = new File(file_in);
		DataInputStream input = new DataInputStream(new BufferedInputStream (new FileInputStream(fin)));
		File fout= new File(file_out);
		DataOutputStream out = new DataOutputStream(new BufferedOutputStream(new FileOutputStream(fout)));
		AES aes = new AES(key.getBytes());//set key
		byte get[] = new byte[16];//get the binary input data 
		byte decrypt[] = new byte[16];
		int cfb_iv,cfb_txt;
		int counter=0;
		int count =0;
		int temp=0;
		int index=0;
		byte[] iv = aes.encrypt(IV.getBytes());
		while(( temp = input.read()) != -1){// if the size of array is 16*8,then call encrypt  function	
			cfb_iv = iv[index] & 0xFF;
			cfb_txt = temp & 0xFF;
			decrypt[index] = (byte) (cfb_iv ^ cfb_txt);
			iv[index] = (byte)temp;
			out.write(decrypt[index]);
			index++;
			if(index == 16){
				iv = aes.encrypt(iv);
				index=0;
			}
		}
		out.flush();
		out.close();
		input.close();
	}
	public static void OFB_encrypt(String IV,String file_in,String file_out,String key)throws Exception{
		File fin = new File(file_in);//use File class to find out the file;
		DataInputStream input = new DataInputStream(new BufferedInputStream (new FileInputStream(fin)));
		File fout = new File(file_out);
		DataOutputStream output = new DataOutputStream(new BufferedOutputStream(new FileOutputStream(fout)));
		int index=0;//the index of byte[] in order to get the data of plaintext;
		int temp =0;
		int ofb_iv,ofb_txt;
		byte ciphertext;	
		AES aes = new AES(key.getBytes());//set key
        byte[] iv = aes.encrypt(IV.getBytes());
		
		while(( temp = input.read()) != -1){// if the size of array is 16*8,then call encrypt  function	
			ofb_iv = iv[index++] & 0xFF;
			ofb_txt = temp;
			ciphertext = (byte) (ofb_iv ^ ofb_txt);
			output.write(ciphertext);
			if(index == 16)
			{
				iv = aes.encrypt(iv);
				index = 0;
			}
		}
		output.flush();
		output.close();	
		input.close();
}
	public static void OFB_decrypt(String IV,String file_in,String file_out,String key)throws Exception{
		File fin = new File(file_in);
		DataInputStream input = new DataInputStream(new BufferedInputStream (new FileInputStream(fin)));
		File fout= new File(file_out);
		DataOutputStream out = new DataOutputStream(new BufferedOutputStream(new FileOutputStream(fout)));
		AES aes = new AES(key.getBytes());//set key
		byte decrypt;
		int ofb_iv,ofb_txt;
		int temp=0;
		int index=0;
		byte[] iv = aes.encrypt(IV.getBytes());
		
		while(( temp = input.read()) != -1){// if the size of array is 16*8,then call encrypt  function	
			ofb_iv = iv[index++] & 0xFF;
			ofb_txt = temp;
			decrypt = (byte) (ofb_iv ^ ofb_txt);
			out.write(decrypt);
			if(index == 16)
			{
				iv = aes.encrypt(iv);
				index = 0;
			}
		}
		out.flush();
		out.close();
		input.close();
	}
	public static void CTR_encrypt(String IV,String file_in,String file_out,String key)throws Exception{
		File fin = new File(file_in);//use File class to find out the file;
		DataInputStream input = new DataInputStream(new BufferedInputStream (new FileInputStream(fin)));
		File fout = new File(file_out);
		DataOutputStream output = new DataOutputStream(new BufferedOutputStream(new FileOutputStream(fout)));
		int index=0;//the index of byte[] in order to get the data of plaintext;
		int temp =0;
		int cfb_iv,cfb_txt;
		int ctr_init,iv_init;
		byte b[] = new byte[16];
		byte ciphertext[] = new byte[16];	
		AES aes = new AES(key.getBytes());//set key
        byte[] ctr = new byte[16];
		byte[] iv = IV.getBytes();
		for(int i=0;i<16;i++)
			ctr[i] = 0;
		for(int i=0;i<16;i++)
		{
			ctr_init = ctr[i]& 0xFF;
			iv_init = iv[i] & 0xFF;
			ctr[i] = (byte)(ctr_init^iv_init);
		}
		byte[] Nonce = aes.encrypt(ctr);
		while(( temp = input.read()) != -1){// if the size of array is 16*8,then call encrypt  function	
			cfb_iv = Nonce[index] & 0xFF;
			cfb_txt = temp & 0xFF;
			ciphertext[index] = (byte) (cfb_iv ^ cfb_txt);
			
			output.write(ciphertext[index]);
			index++;
			if(index == 16){
				ctr = Counter(ctr);
				for(int i=0;i<16;i++)
				{
					ctr_init = ctr[i]& 0xFF;
					iv_init = iv[i] & 0xFF;
					ctr[i] = (byte)(ctr_init^iv_init);
				}
				Nonce = aes.encrypt(ctr);
				index=0;
			}
		}
		output.flush();
		output.close();	
		input.close();
	}
	public static void CTR_decrypt(String IV,String file_in,String file_out,String key)throws Exception{
		File fin = new File(file_in);
		DataInputStream input = new DataInputStream(new BufferedInputStream (new FileInputStream(fin)));
		File fout= new File(file_out);
		DataOutputStream out = new DataOutputStream(new BufferedOutputStream(new FileOutputStream(fout)));
		AES aes = new AES(key.getBytes());//set key
		byte get[] = new byte[16];//get the binary input data 
		byte decrypt[] = new byte[16];
		int cfb_iv,cfb_txt;
		int temp=0;
		int index=0;
		int ctr_init,iv_init;
		byte[] ctr = new byte[16];
		byte[] iv = IV.getBytes();
		for(int i=0;i<16;i++)
			ctr[i] = 0;
		for(int i=0;i<16;i++)
		{
			ctr_init = ctr[i]& 0xFF;
			iv_init = iv[i] & 0xFF;
			ctr[i] = (byte)(ctr_init^iv_init);
		}
		byte[] Nonce = aes.encrypt(ctr);
		while(( temp = input.read()) != -1){// if the size of array is 16*8,then call encrypt  function	
			cfb_iv = Nonce[index] & 0xFF;
			cfb_txt = temp & 0xFF;
			decrypt[index] = (byte) (cfb_iv ^ cfb_txt);
			out.write(decrypt[index]);
			index++;
			if(index == 16){
				ctr = Counter(ctr);
				for(int i=0;i<16;i++)
				{
					ctr_init = ctr[i]& 0xFF;
					iv_init = iv[i] & 0xFF;
					ctr[i] = (byte)(ctr_init^iv_init);
				}
				Nonce = aes.encrypt(ctr);
				index=0;
			}
		}
		out.flush();
		out.close();
		input.close();
	}
	public static byte[] Counter(byte counter[]){
		int index =15,in=15;
			counter[index]++;
			if(counter[index] == 127)
			{
				for(int j=15;j>0;j--)
				{
					if(counter[j] == 127)
					{
						counter[j-1]++;
						counter[j]=0;
					}
					else if(counter[j]<127)
						continue;
				}
			}
		return counter;

	}
}
