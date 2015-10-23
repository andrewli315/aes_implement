package aes;
import java.io.* ;
import java.util.*;
public class encrypt{
	public static void main(String[] args) throws Exception{
		long beginTime = System.nanoTime();
		String route_en,route_de,route_en_in,route_de_in;
		File enc = new File(args[2]);
		enc.mkdir();
			
		File dec = new File(args[3]);
		dec.mkdir();
		
		File enc_file = new File(args[1]);
		File[] file_read = enc_file.listFiles();
	
		String file_name[] = enc_file.list();
		
		for(int i=0;i <file_name.length ;i++){
			if(file_read[i].isDirectory()){
				continue;
			}
			else{
				route_en = new String(args[2]+File.separator+file_name[i]);//the route of encrypted data output file
				route_de = new String(args[3]+File.separator+file_name[i]);//the route of decrypted data output file
				route_en_in = new String(args[1]+File.separator+file_name[i]);//the route of plaintext input file
				route_de_in = new String(args[2]+File.separator+file_name[i]);//the route of encrypted-data input file
				encrypt(route_en_in,route_en,args[0]);
				decrypt(route_de_in,route_de,args[0]);		
			}
		}
		long endTime = System.nanoTime();
        System.out.println("Program cost time:\t" + (double) (endTime - beginTime) / 1000000 + " ms");
	}
	public static void encrypt(String file_in,String file_out,String key)throws Exception{
		File fin = new File(file_in);//use File class to find out the file;
		DataInputStream input = new DataInputStream(new BufferedInputStream (new FileInputStream(fin)));
		File fout = new File(file_out);
		DataOutputStream output = new DataOutputStream(new BufferedOutputStream(new FileOutputStream(fout)));
		int index=0;//the index of byte[] in order to get the data of plaintext;
		int temp =0;
		Random ran = new Random();//to expand the encryption array if the plaintext is not satisfied the 128 bits
		byte b[] = new byte[16];
		String plaintext;	
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
			for(int i =index+1;i<=15;i++)
				b[i] = (byte)ran.nextInt(31);//in the ascii code, from 32 to 126 is printable character we use
			//,so I select a range that is present the control code.
			byte[] ciphertext = aes.encrypt(b);
			output.write(ciphertext);
		}
		output.flush();
		output.close();	
		input.close();
	}
	public static void decrypt(String file_in,String file_out,String key)throws Exception{
		File fin = new File(file_in);
		DataInputStream input = new DataInputStream(new BufferedInputStream (new FileInputStream(fin)));
		File fout= new File(file_out);
		DataOutputStream out = new DataOutputStream(new BufferedOutputStream(new FileOutputStream(fout)));
		AES aes = new AES(key.getBytes());//set key
		String cipher;
		byte get[] = new byte[16];//get the binary input data 
		int temp=0;
		int index=0;
		while((temp = input.read()) != -1){	
			get[index] = (byte) temp;
			if(index == 15){ // if the size of array is 16*8,then call decrypt  function
				index =0;
				byte[] decrypt = aes.decrypt(get);
				
				for(int i =0;i<16;i++){//delete the padding character in encryption process
					if(decrypt[i]<=31)
						decrypt[i]=0;
					out.write(decrypt[i]);
					get[i] = 0;
				}
			}
			else
				index++;
		}
		out.close();
		input.close();
	}
}
