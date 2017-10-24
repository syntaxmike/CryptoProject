package SDES;

import java.util.ArrayList;
import java.util.List;
import java.io.*;

/* From http://mercury.webster.edu/aleshunas/COSC%205130/G-SDES.pdf
 * 
 * The S-DES encryption algorithm takes an 8-bit block of plaintext (example: 10111101)
and a 10-bit key as input and produces an 8-bit block of ciphertext as output. The S-DES
decryption algorithm takes an 8-bit block of ciphertext and the same 10-bit key used to produce
that ciphertext as input and produces the original 8-bit block of plaintext.


The encryption algorithm involves five functions: an initial permutation (IP); a complex
function labeled fK, which involves both permutation and substitution operations and depends on
a key input; a simple permutation function that switches (SW) the two halves of the data; the
function fK again; and finally a permutation function that is the inverse of the initial permutation
(IP-1). As was mentioned in Chapter 2, the use of multiple stages of permutation and substitution
results in a more complex algorithm, which increases the difficulty of cryptanalysis.
 */

public class SDES {
	
	//Substitution Box 0
	public static byte[][] s0 = {{1, 0, 3, 2}, {3, 2, 1, 0}, {0, 2, 1, 3}, {3, 1, 3, 2}};
	
	//Substitution Box 1
	public static byte[][] s1 = {{0, 1, 2, 3}, {2, 0, 1, 3}, {3, 0, 1, 0}, {2, 1, 0, 3}};
	
	public static byte[] appendArray(byte[] a, byte[] b){
		byte[] c = new byte[a.length + b.length];
		System.arraycopy(a, 0, c, 0, a.length);
		System.arraycopy(b, 0, c, a.length, b.length);
		
		return c;
	}
	
	public static byte[] shiftLeft(byte[] shiftArr) {
		byte[] shiftTempArr = new byte[shiftArr.length];
		for(int i = 0; i < shiftArr.length; i++){
			if(i == shiftArr.length - 1) {
				shiftTempArr[i] = shiftArr[0];
			} else {
				shiftTempArr[i] = shiftArr[i + 1];
			}
		}
		
		return shiftTempArr;
	}
	
	public static List<byte[]> keyGeneration(byte[] rawKey){
		
		// pK[10](k1, k2, k3, k4, k5, k6, k7, k8, k9, k10) = (k3, k5, k2, k7, k4, k10,
		// k1, k9, k8, k6)
		// pK[8] = (k6, k3, k7, k4, k8, k5, k10, k9)
		List<byte[]> keys = new ArrayList<byte[]>();
		
		
		//Key Permutation pKey[10].
		byte[] permutationKey = new byte[10];
		permutationKey[0] = rawKey[2];
		permutationKey[1] = rawKey[4];
		permutationKey[2] = rawKey[1];
		permutationKey[3] = rawKey[6];
		permutationKey[4] = rawKey[3];
		permutationKey[5] = rawKey[9];
		permutationKey[6] = rawKey[0];
		permutationKey[7] = rawKey[8];
		permutationKey[8] = rawKey[7];
		permutationKey[9] = rawKey[5];
		
		//This performs a left shift (LS-1), or rotation, separately
		//on the first five bits and second five bits.
		byte[] leftSide = new byte[5];
		int leftCounter = 0;
		byte[] rightSide = new byte[5];
		int rightCounter = 0;
		
		//Defining the left and right sides of the key, then shifting them to the left.
		for(int i = 0; i < permutationKey.length; i++) {
			if(i < 5) {
				leftSide[leftCounter++] = permutationKey[i];
			} else {
				rightSide[rightCounter++] = permutationKey[i];
			}
		}
			
		//Shift to the left once for the first key.
		leftSide = shiftLeft(leftSide);
		rightSide = shiftLeft(rightSide);
		
		byte[] leftShift_1 = appendArray(leftSide, rightSide);

		byte[] key_1 = new byte[8];
		key_1[0] = leftShift_1[5];
		key_1[1] = leftShift_1[2];
		key_1[2] = leftShift_1[6];
		key_1[3] = leftShift_1[3];
		key_1[4] = leftShift_1[7];
		key_1[5] = leftShift_1[4];
		key_1[6] = leftShift_1[9];
		key_1[7] = leftShift_1[8];
		keys.add(key_1);

		// Shift left two more times for both left and right to get the second key.
		leftSide = shiftLeft(leftSide);
		leftSide = shiftLeft(leftSide);
		rightSide = shiftLeft(rightSide);
		rightSide = shiftLeft(rightSide);
		
		byte[] leftShift_2 = appendArray(leftSide, rightSide);

		byte[] key_2 = new byte[8];
		key_2[0] = leftShift_2[5];
		key_2[1] = leftShift_2[2];
		key_2[2] = leftShift_2[6];
		key_2[3] = leftShift_2[3];
		key_2[4] = leftShift_2[7];
		key_2[5] = leftShift_2[4];
		key_2[6] = leftShift_2[9];
		key_2[7] = leftShift_2[8];
		keys.add(key_2);

		return keys;
		
	}
	
	public static byte concatByte(byte one, byte two) {
		byte concat = 0;
		
		concat = (byte) ((one << 1) | concat);
		concat = (byte) (two | concat);
		
		return concat;
	}
	
	public static byte[] extractBit(byte row, byte column, byte[][] sBox) {
		byte[] extracted = new byte[2];
		
		byte valueRetrieved = sBox[row][column];
		extracted[0] = (byte) (1 & (valueRetrieved >> 1));
		extracted[1] = (byte) (1 & valueRetrieved);
		
		return extracted;
	}
	
	
	public static byte[] function(byte[] rightSide, byte[] key) {
		byte[] result = new byte[4];

		byte[] EP = new byte[8];
		EP[0] = rightSide[3];
		EP[1] = rightSide[0];
		EP[2] = rightSide[1];
		EP[3] = rightSide[2];
		EP[4] = rightSide[1];
		EP[5] = rightSide[2];
		EP[6] = rightSide[3];
		EP[7] = rightSide[0];

		// Apply XOR functionality to EP with key1.
		byte[] XORBit = new byte[8];
		XORBit[0] = (byte) (EP[0] ^ key[0]);
		XORBit[1] = (byte) (EP[1] ^ key[1]);
		XORBit[2] = (byte) (EP[2] ^ key[2]);
		XORBit[3] = (byte) (EP[3] ^ key[3]);
		XORBit[4] = (byte) (EP[4] ^ key[4]);
		XORBit[5] = (byte) (EP[5] ^ key[5]);
		XORBit[6] = (byte) (EP[6] ^ key[6]);
		XORBit[7] = (byte) (EP[7] ^ key[7]);

		// Apply final fK permutation. Look at s0 and s1 for the appropriate
		// location.
		byte[] producedfK = appendArray(
				extractBit(concatByte(XORBit[0], XORBit[3]), concatByte(XORBit[1], XORBit[2]), s0),
				extractBit(concatByte(XORBit[4], XORBit[7]), concatByte(XORBit[5], XORBit[6]), s1));

		result[0] = producedfK[1];
		result[1] = producedfK[3];
		result[2] = producedfK[2];
		result[3] = producedfK[0];

		return result;
	}
	
	public static byte[] encrypt(byte[] rawKey, byte[] plaintext) {
		// IP = (k2, k6, k3, k1, k4, k8, k5, k7)
		// IP-1 = (k4, k1, k3, k5, k7, k2, k8, k6)
		
		//This holds Keys 1 and 2
		List<byte[]> generatedKey = keyGeneration(rawKey);
		
		//Apply initial permutation from plain text.
		byte[] initialPermutation = new byte[8];
		initialPermutation[0] = plaintext[1];
		initialPermutation[1] = plaintext[5];
		initialPermutation[2] = plaintext[2];
		initialPermutation[3] = plaintext[0];
		initialPermutation[4] = plaintext[3];
		initialPermutation[5] = plaintext[7];
		initialPermutation[6] = plaintext[4];
		initialPermutation[7] = plaintext[6];
		
		/* After initial permutation, we apply fK(L, R) = (L XOR f(R, SK), R)
		 * L = 4 left bits, R = 4 right bits, and SK = sub key
		 * Need to expand the left 4 bits to 8 so it matches the key.
		 * E/P = (4, 1, 2, 3, 2, 3, 4, 1)
		 */
		byte[] leftSide = new byte[4];
		int leftCounter = 0;
		byte[] rightSide = new byte[4];
		int rightCounter = 0;
		
		for(int i = 0; i < initialPermutation.length; i++) {
			if(i < 4) {
				leftSide[leftCounter++] = initialPermutation[i];
			} else {
				rightSide[rightCounter++] = initialPermutation[i];
			}
		}
		
		//Produce the byte using a function to produce fK.
		byte[] F1 = function(rightSide, generatedKey.get(0));
		byte[] leftXORF1 = new byte[4];
		for(int i = 0; i < leftSide.length; i++) {
			leftXORF1[i] = (byte) (leftSide[i] ^ F1[i]);
		}
		
		//Switch out the left and right side and perform the function again.
		byte[] F2 = function(leftXORF1, generatedKey.get(1));
		byte[] rightXORF2 = new byte[4];
		for(int i = 0; i < rightSide.length; i++) {
			rightXORF2[i] = (byte) (rightSide[i] ^ F2[i]);
		}
		
		byte[] result = appendArray(rightXORF2, leftXORF1);
		byte[] reverseInitialPermutation = new byte[8];
		
		reverseInitialPermutation[0] = result[3];
		reverseInitialPermutation[1] = result[0];
		reverseInitialPermutation[2] = result[2];
		reverseInitialPermutation[3] = result[4];
		reverseInitialPermutation[4] = result[6];
		reverseInitialPermutation[5] = result[1];
		reverseInitialPermutation[6] = result[7];
		reverseInitialPermutation[7] = result[5];
		
		return reverseInitialPermutation;
		
	}


	public static byte[] decrypt(byte[] rawKey, byte[] ciphertext) {
		
		//This holds Keys 1 and 2
				List<byte[]> generatedKey = keyGeneration(rawKey);
				
				//Apply initial permutation from plain text. IP - 1
				byte[] initialPermutation = new byte[8];
				initialPermutation[0] = ciphertext[1];
				initialPermutation[1] = ciphertext[5];
				initialPermutation[2] = ciphertext[2];
				initialPermutation[3] = ciphertext[0];
				initialPermutation[4] = ciphertext[3];
				initialPermutation[5] = ciphertext[7];
				initialPermutation[6] = ciphertext[4];
				initialPermutation[7] = ciphertext[6];
				
				/* After initial permutation, we apply fK(L, R) = (L XOR f(R, SK), R)
				 * L = 4 left bits, R = 4 right bits, and SK = subkey
				 * Need to expand the left 4 bits to 8 so it matches the key.
				 * E/P = (4, 1, 2, 3, 2, 3, 4, 1)
				 */
				byte[] leftSide = new byte[4];
				int leftCounter = 0;
				byte[] rightSide = new byte[4];
				int rightCounter = 0;
				
				for(int i = 0; i < initialPermutation.length; i++) {
					if(i < 4) {
						leftSide[leftCounter++] = initialPermutation[i];
					} else {
						rightSide[rightCounter++] = initialPermutation[i];
					}
				}
				
				//Produce the byte using a function to produce fK.
				byte[] F1 = function(rightSide, generatedKey.get(1));
				byte[] leftXORF1 = new byte[4];
				for(int i = 0; i < leftSide.length; i++) {
					leftXORF1[i] = (byte) (leftSide[i] ^ F1[i]);
				}
				
				//Switch out the left and right side and perform the function again.
				byte[] F2 = function(leftXORF1, generatedKey.get(0));
				byte[] rightXORF2 = new byte[4];
				for(int i = 0; i < rightSide.length; i++) {
					rightXORF2[i] = (byte) (rightSide[i] ^ F2[i]);
				}
				
				byte[] result = appendArray(rightXORF2, leftXORF1);
				byte[] reverseInitialPermutation = new byte[8];
				
				reverseInitialPermutation[0] = result[3];
				reverseInitialPermutation[1] = result[0];
				reverseInitialPermutation[2] = result[2];
				reverseInitialPermutation[3] = result[4];
				reverseInitialPermutation[4] = result[6];
				reverseInitialPermutation[5] = result[1];
				reverseInitialPermutation[6] = result[7];
				reverseInitialPermutation[7] = result[5];
				
				return reverseInitialPermutation;
		
	}

	public static String byteToString(byte[] temp) {
		String byteStr = "";
		for( byte a : temp) {
			byteStr = byteStr + String.valueOf(a);
		}
		
		return byteStr;
	}
	
	public static byte[] stringToByteArray(String str) {
		String[] strList = str.split("");
		byte[] byteList = new byte[str.length()];
		
		for(int i = 0; i < strList.length; i++) {
			byteList[i] = Byte.valueOf(strList[i]);
		}
		
		return byteList;
	}
	
	public static void main(String[] args) {
		// ========== Parsing the text file =======================================
		String filepath = "src\\resources\\SDES.txt";
		File file = new File(filepath);
				
		List<String> original = new ArrayList<String>();
		List<ArrayList<String>> applyAnswer = new ArrayList<ArrayList<String>>();
		try(BufferedReader br = new BufferedReader(new FileReader(file))){
			int currRow = 0;
			String str = br.readLine(); // We skip the first line
			original.add(str);
			while((str = br.readLine()) != null){
				original.add(str);
				applyAnswer.add(new ArrayList<String>());
				for( String s : str.split(" ")){
					if(!s.isEmpty()){
						applyAnswer.get(currRow).add(s);
						}
					}
						currRow ++;
			}
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
				
		// ========== Printing the text file =======================================
		System.out.println("========== Original SDES ============");
		for( String o : original){
			System.out.println(o);
		}
		System.out.println("=========== Solved SDES =============");
		System.out.printf("%-15s%-15s%-15s", "Raw Key", "Plaintext", "CipherText");
		System.out.println();
		for ( ArrayList<String> cryptoList : applyAnswer){
			boolean solved = false; // This variable is to check whether if a row is "filled" or not ( requires answer )
					
			for(int i = 0; i < cryptoList.size(); i ++){
				if(cryptoList.get(i).equals("?")){
							
				if(i == 1){ // If plain text requires answer
					String plaintext = byteToString(decrypt(stringToByteArray(cryptoList.get(0)), stringToByteArray(cryptoList.get(2))));
					System.out.printf("%-15s%-15s%-15s", cryptoList.get(0), plaintext, cryptoList.get(2));
					solved = true;
					break;
					}
				if(i == 2){ // If cipher text requires answer
					String ciphertext = byteToString(encrypt(stringToByteArray(cryptoList.get(0)), stringToByteArray(cryptoList.get(1))));
					System.out.printf("%-15s%-15s%-15s", cryptoList.get(0), cryptoList.get(1), ciphertext);
					solved = true;
					break;
					}
				}
			}
			if(!solved){
				System.out.printf("%-15s%-15s%-15s", cryptoList.get(0), cryptoList.get(1), cryptoList.get(2));
			}
			System.out.println();
		}
	}
}
