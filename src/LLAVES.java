/* **** PRIMERAMENTE IMPORTAMOS LAS CLASES QUE SE REQUIEREN **** */
import javax.crypto.Cipher; // proporciona la funcionalidad del cifrado y descifrado criptografico (usare RSA)
import java.security.*; // contiene las clases que se necesitan para la creacion de 
                        // las llaves publica y privada y la firma 
                        // (y su verificacion): keypair, keygenerator, publickey, privatekey, signature. 
                        // Para no poner 5 lineas (una por cada paquete/clase importada) se escribe el asterisco.
import java.util.Base64; // para codificador y decodificar el texto encriptado en base64
import static java.nio.charset.StandardCharsets.UTF_8; // convertir el texto cifrado/descifrado en UTF8
/**
 *
 * @author Dany
 */
public class LLAVES {
    // GENERAR LAS LLAVES: PUBLICA Y PRIVADA
    public KeyPair generarLlaves() throws Exception { // metodo que devuelve el tipo KeyPair (que son las llaves)
        // instancia del generador de claves (del tipo algoritmo RSA - asimetrico)
        KeyPairGenerator generadorllaves = KeyPairGenerator.getInstance("RSA"); 
        //Inicializo el generador de pares de llaves de longitud 2048 bits y aleatorios (securerandom)
        generadorllaves.initialize(2048, new SecureRandom()); 
        // genero el par de llaves y lo asigno a la variable del tipo (par de) llaves
        KeyPair parllaves = generadorllaves.generateKeyPair();
        return parllaves; // regreso las llaves para ser usadas
    }    
    // ENCRIPTAR MENSAJE
    // metodo que devuelve un string (encriptado), se pasa por parametros el texto a encriptar y la llave publica
    public String encriptar(String texto, PublicKey llavepublica) throws Exception {
        // instancia del cifrado (del tipo algoritmo RSA)
        Cipher cifrar = Cipher.getInstance("RSA");
        // iniciamos el cifrado en modo ENCRIPTAR con la llave publica para cifrar el mismo
        cifrar.init(Cipher.ENCRYPT_MODE, llavepublica);
        // Para encriptar, necesitamos pasar el texto sin formato (lo convertimos 
        // en UTF_8 que nos da un arreglo de bytes) como parámetro al método doFinal () de la instancia de cifrado (cifrar)
        byte[] textocifrado = cifrar.doFinal(texto.getBytes(UTF_8));
        // regresamos el string codificado en Base64 (se codifica el texto sin separación de línea
        // la salida se asigna a un conjunto de caracteres en A-Za-z0-9+/
        return Base64.getEncoder().encodeToString(textocifrado);
    }    
    // DESCENCRIPTAR MENSAJE
    // metodo que devuelve un string (desencriptado), se pasa por parametros el texto a desencriptar y la llave privada
    public String desencriptar(String textoencriptado, PrivateKey llaveprivada) throws Exception {
        // decodificamos en texto encriotado en base64 a un arreglo de bytes 
        byte[] bytes = Base64.getDecoder().decode(textoencriptado);
        // instancia del cifrado (para descifrar)(del tipo algoritmo RSA)
        Cipher descifrar = Cipher.getInstance("RSA");
        // iniciamos el descifrado en modo DESENCRIPTAR con la llave privada para descifrar el mismo
        descifrar.init(Cipher.DECRYPT_MODE, llaveprivada);
        // regresamos el texto/mensaja original
        return new String(descifrar.doFinal(bytes), UTF_8);
    }        
    // FIRMA DIGITAL
    // devuelve un string con la firma digital del mensaje, por parametros el texto/mensaje y la llave privada
    public String firma(String texto, PrivateKey llaveprivada) throws Exception {
        // instancia de la firma del tipo SHA256withRSA 
        Signature firmaprivada = Signature.getInstance("SHA256withRSA");
        // la inicializamos con la llave privada
        firmaprivada.initSign(llaveprivada);
        // actualizamos la firma con el texto/mensaje convertido en UTF_8
        firmaprivada.update(texto.getBytes(UTF_8));
        // generamos la firma
        byte[] firmadigital = firmaprivada.sign();
        // regresamos el string (la firma) codificado en Base64 (se codifica el texto sin separación de línea
        // la salida se asigna a un conjunto de caracteres en A-Za-z0-9+/ 
        return Base64.getEncoder().encodeToString(firmadigital);
    }    
    // VERIFICAR FIRMA DIGITAL  
    // devuelve un valor booleano (verdadero/falso) sobre la firma digital verificad del mensaje
    // por parametros el texto/mensaje y la llave publica
    public boolean verificar(String texto, String firma, PublicKey llavepublica) throws Exception {
        // instancia de la firma del tipo SHA256withRSA 
        Signature firmapublica = Signature.getInstance("SHA256withRSA");
        // inicializamos la verificacion con la llave privada
        firmapublica.initVerify(llavepublica);
        // actualizamos la firma con el texto/mensaje convertido en UTF_8
        firmapublica.update(texto.getBytes(UTF_8));
        // asignamos la firma decodificada en Base64 (se codifica el texto sin separación de línea
        // la salida se asigna a un conjunto de caracteres en A-Za-z0-9+/
        byte[] bytesdefirma = Base64.getDecoder().decode(firma);
        // verificamos la firma
        return firmapublica.verify(bytesdefirma);
    } 
}
