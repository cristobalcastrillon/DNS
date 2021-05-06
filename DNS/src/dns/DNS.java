package dns;

import java.io.*;
import java.net.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Random;

public class DNS {
        
    public static void main(String[] args) throws IOException {

        try {
            //Listado de registros tipo A
            ArrayList<ArrayList<String>> registros = new ArrayList<>();
            
            String filePath = "/Users/cristobalcastrilonbalcazar/REDES/DNS/src/files/masterFile.txt";
            
            File masterFile = new File(filePath); //Pasarle el path completo al constructor del file
            FileReader masterReader = new FileReader(masterFile);
            BufferedReader reader = new BufferedReader(masterReader);
            
            String fileLine;
            
            while((fileLine = reader.readLine()) != null){
                String[] col = fileLine.split(",");
                ArrayList<String> filaList = new ArrayList<>();
                filaList.add(col[0]);
                filaList.add(col[1]);
                filaList.add(col[2]);
                filaList.add(col[3]);
                filaList.add(col[4]);
                filaList.add(col[5]);
                
                registros.add(filaList);
            }
            
            reader.close();
            
            //Socket al puerto DNS (#53)
            DatagramSocket socketUDP = new DatagramSocket(53);
            
            //Messages carried by UDP are restricted to 512 bytes (not counting the IP or UDP headers)
            byte[] buffer = new byte[512];
            
            while (true) {
                // Construimos el DatagramPacket para recibir peticiones
                //NOTA: El Datagram es un Datagrama UDP (tamaño de UDP Datagram)
                DatagramPacket peticion = new DatagramPacket(buffer, buffer.length);
                
                // Leemos una petición del DatagramSocket
                
                socketUDP.receive(peticion);

                System.out.println("Datagrama recibido del host: " + peticion.getAddress());
                System.out.println("Puerto remoto: " + peticion.getPort());

                //queryResponseDataMap: HashMap de Campos compartidos entre Query y Response.
                HashMap<String, String> queryResponseDataMap = new HashMap<>();
                ArrayList<byte[]> queryData = extraerData(peticion.getData(), queryResponseDataMap);

                ArrayList<Byte> respuestaBytes = crearRespuesta(queryResponseDataMap, registros, queryData);
                byte[] respuesta = new byte[512];
                if(respuestaBytes != null){
                    respuesta = fromByteListToArray(respuestaBytes);
                    // Construimos el DatagramPacket para enviar la respuesta
                    DatagramPacket responsePacket = new DatagramPacket(respuesta, respuesta.length, peticion.getAddress(), peticion.getPort());
                    socketUDP.send(responsePacket);
                    
                    System.out.println("Datagrama enviado al host: " + responsePacket.getAddress());
                    System.out.println("Puerto remoto: " + responsePacket.getPort());
                }
                else{
                    InetAddress dnsIP = InetAddress.getByName("8.8.8.8");
                    DatagramPacket recQuery = new DatagramPacket(peticion.getData(), peticion.getLength(), dnsIP, 53);
                    socketUDP.send(recQuery);
                    // Construimos el DatagramPacket para enviar la respuesta
                    DatagramPacket recResponse = new DatagramPacket(buffer, buffer.length);
                    socketUDP.receive(recResponse);
                    recResponse.setAddress(peticion.getAddress());
                    recResponse.setPort(peticion.getPort());
                    socketUDP.send(recResponse);
                    
                    System.out.println("Datagrama enviado al host: " + recResponse.getAddress());
                    System.out.println("Puerto remoto: " + recResponse.getPort());
                } 
            }

        } catch (SocketException e) {
            System.out.println("Socket: " + e.getMessage());
        } catch (IOException e) {
            System.out.println("IO: " + e.getMessage());
        }
    }

    private static ArrayList<Byte> crearRespuesta(HashMap<String, String> queryResponseDataMap, ArrayList<ArrayList<String>> registros, ArrayList<byte[]> camposByte) {
        
        ArrayList<Byte> response = new ArrayList<>();
        String responseStr = "";
        
        String trID = queryResponseDataMap.get("ID");
        String QR = "1";
        String opCode = queryResponseDataMap.get("OPCODE");
        String qdCount = queryResponseDataMap.get("QDCOUNT");
        String qName = queryResponseDataMap.get("QNAME");
        
        String AA = "0";
        
        ArrayList<ArrayList<String>> foundName = findInMasterFile(qName, registros);
        
        if(foundName != null){
            Integer anCount = foundName.size();
            String anCountStr = String.format("%16s", Integer.toBinaryString(anCount)).replace(' ', '0');
            
            AA = "1";
            String TC = "0";
            String RD = "1";
            String RA = "0";
            String Z = "000";
            String RCODE = "0000";
            String NSCOUNT = "0000000000000000";

            responseStr += trID;
            responseStr += QR + opCode + AA + TC + RD; 
            responseStr += RA + Z + RCODE;
            responseStr += qdCount;
            responseStr += anCountStr;
            //NSCOUNT + ARCOUNT (Idéntico a NSCOUNT)
            responseStr += NSCOUNT + NSCOUNT;

            for(int i = 0; i < responseStr.length(); i += 8){
                Integer octet = Integer.parseInt(responseStr.substring(i, i + 8), 2);
                byte octetByte = octet.byteValue();
                response.add(octetByte);
            }

            //Agregando QNAME a la respuesta (bytes)...
            for(int i = 0; i < camposByte.get(7).length; i++){
                response.add(camposByte.get(7)[i]);
            }
            byte terminador = 0;
            response.add(terminador);
            
            //Agregando QTYPE a la respuesta (bytes)...
            byte uno = 1;
            response.add(terminador);
            response.add(uno);
            
            //Agregando QCLASS a la respuesta (bytes)...
            //Qué orden debe ser [0][1] o [1][0]?
            //response.add();
            response.add(camposByte.get(9)[0]);
            response.add(camposByte.get(9)[1]);
            
            //ArrayList para guardar los resource records
            ArrayList<Byte> rr_response = new ArrayList<>();
            
            for(int rrCount = 0; rrCount < anCount; rrCount++){
                //Agregando NAME a la respuesta (bytes)...
                //for(int i = 0; i < camposByte.get(7).length; i++){
                //    rr_response.add(camposByte.get(7)[i]);
                //}
                Integer[] namePtrIntVals = {192,12};
                
                byte namePtr1 = namePtrIntVals[0].byteValue();
                byte namePtr2 = namePtrIntVals[1].byteValue();
                rr_response.add(namePtr1);
                rr_response.add(namePtr2);

                //TYPE
                byte[] TYPE = {0,0};
                String tipoRegistro = foundName.get(rrCount).get(3);
                int RD_LENGTH = 4;
                
                if(tipoRegistro.equals("A")){
                    //Agregando TYPE: A = 1 (0000000000000001)
                    TYPE[1] = 1;
                    RD_LENGTH = 4;
                }
                if(tipoRegistro.equals("AAAA")){
                    //Agregando TYPE: AAAA = 28 (0000000000011100)
                    TYPE[1] = 28;
                    RD_LENGTH = 16;
                }
                rr_response.add(TYPE[0]);
                rr_response.add(TYPE[1]);

                //CLASS
                byte[] CLASS = {0,0};
                String claseRegistro = foundName.get(rrCount).get(2);
                if(claseRegistro.compareTo("IN") == 0){
                    //Agregando CLASS: IN = 1 (0000000000000001)
                    CLASS[1] = 1;
                }
                rr_response.add(CLASS[0]);
                rr_response.add(CLASS[1]);
                
                //TTL
                byte[] ttl = convertIntegerToByteArray(300, 4, false);
                for (byte b : ttl) {
                    rr_response.add(b);
                }
                
                //RD_LENGTH
                byte[] rdLength = convertIntegerToByteArray(RD_LENGTH, 2, false);
                for (byte b : rdLength) {
                    rr_response.add(b);
                }
                
                //R_DATA
                String ipAddr = "";
                ipAddr = foundName.get(rrCount).get(5);
                String[] ipAddr_sin = ipAddr.split("\\.");
                
                byte[] rData = new byte[4];
                for(int i = 0; i < 4; i++){
                    Integer a = Integer.parseInt(ipAddr_sin[i]);
                    byte b = a.byteValue();
                    rr_response.add(b);
                }
            }
            
            response.addAll(rr_response);
        }
        else{
            response = null;
        }
        return response;
    }
    
    private static ArrayList<byte[]> extraerData(byte[] data, HashMap<String, String> queryResponseDataMap) {
        //ArrayList where query data is stored
        ArrayList<byte[]> queryData = new ArrayList<>();
        
        byte[] trID = {0,0};
        int index = 0;
        String trIDStr = "";
        while(index < 2){
            trID[index] = data[index];
            trIDStr += toBits(data[index]);
            index++;
        }
        
        //QR, OpCode & Banderas (sin RA)
        byte[] thirdByte = {0};
        thirdByte[0] = data[index++];

        //Extrayendo OPCode (campo compartido entre Query y Respuesta)
        String thirdByteStr = toBits(thirdByte[0]);
        String opCode = thirdByteStr.substring(1, 5);

        //RA
        //Z (Reserved for Future Use) = 4 bits en 0
        //RCODE 0 = No Error
        byte[] razRcode = {0};
        razRcode[0] = data[index++];

        //QDCOUNT
        String qdCountStr = "";
        byte[] qdCount = {0,0};
        for(int i = 0; i < 2; i++){
            qdCount[i] = data[index];
            qdCountStr += toBits(data[index]);
            index++;
        }

        //ANCOUNT
        byte[] anCount = {0,0};
        for(int i = 0; i < 2; i++){
            anCount[i] = data[index];
            index++;
        }

        //NSCOUNT
        byte[] nsCount = {0,0};
        for(int i = 0; i < 2; i++){
            nsCount[i] = data[index];
            index++;
        }

        //ARCOUNT
        byte[] arCount = {0,0};
        for(int i = 0; i < 2; i++){
            arCount[i] = data[index];
            index++;
        }
        
        //Armando el ArrayList de byte[]...
        queryData.add(trID);
        queryData.add(thirdByte);
        queryData.add(razRcode);
        queryData.add(qdCount);
        queryData.add(anCount);
        queryData.add(nsCount);
        queryData.add(arCount);

        //Question section
        //qdCountInt: qdCount en entero
        int qdCountInt = Integer.parseInt(qdCountStr, 2);
        for(int i = 0; i < qdCountInt; i++){
            //QNAME
            
            //Label: cada una de los strings (sin los puntos) que contiene un URL
            //Ejemplo: www.google.com (www, google, com)
            //int j = 0;
            String q_name_lengthStr = ""; 
            int labelLength = 0;
            
            //String donde se va a almacenar el nombre de dominio
            String name = "";
            
            ArrayList<Byte> qNameByte = new ArrayList<>();
            
            while(data[index] != 0){
                
                qNameByte.add(data[index]);
                q_name_lengthStr = toBits(data[index++]);
                labelLength = Integer.parseInt(q_name_lengthStr, 2);
                
                //Prueba
                //System.out.println(labelLength);
                
                byte[] byteName = new byte[labelLength];
                for(int k = 0; k < labelLength; k++){
                    byteName[k] = data[index];
                    qNameByte.add(byteName[k]);
                    index++;
                }

                //Label copiado al nombre
                name += new String(byteName) + '.';
            }

            name = name.substring(0, name.length()-1);
            byte[] qNameByteTrim = fromByteListToArray(qNameByte);
            
            //PRUEBA
            //System.out.println(qNameByte);
            
            //QNAME index = 7
            queryData.add(qNameByteTrim);
            
            //QTYPE index = 8
            byte[] qType = {0,0};
            qType[0] = data[index++];
            qType[1] = data[index++];
            queryData.add(qType);
            
            //QCLASS index 9
            byte[] qClass = {0,0};
            qClass[1] = data[index++];
            qClass[0] = data[index++];
            queryData.add(qClass);
            
            queryResponseDataMap.put("ID", trIDStr);
            queryResponseDataMap.put("OPCODE", opCode);
            queryResponseDataMap.put("QDCOUNT", qdCountStr);
            queryResponseDataMap.put("QNAME", name);

            //QTYPE
            //QCLASS
        }
        
        return queryData;
    }
     
    private static String toBits(final byte val) {
        final StringBuilder result = new StringBuilder();

        for (int i=0; i<8; i++) {
                result.append((int)(val >> (8-(i+1)) & 0x0001));
        }

        return result.toString();
    }
    
    private static ArrayList<ArrayList<String>> findInMasterFile(String name, ArrayList<ArrayList<String>> registros){
        ArrayList<ArrayList<String>> registrosNombre = null;
        registrosNombre = new ArrayList<>();
        for(ArrayList<String> row : registros){
            if(row.get(0).compareTo(name) == 0){
                registrosNombre.add(row);
            }
        }
        if(!registrosNombre.isEmpty())
            return registrosNombre;
        return null; //Cuando se retorna NULL, se debe remitir el query a otro DNS
    }
    
    private static byte[] fromByteListToArray(ArrayList<Byte> byteList){
        int n = byteList.size();
        byte[] out = new byte[n];
        for (int i = 0; i < n; i++) {
          out[i] = byteList.get(i);
        }
        return out;
    }
   
    
    public static final byte[] convertIntegerToByteArray(int value,
            int bytes, boolean revers) {
        if (bytes == 1 && !revers) {
            return new byte[] { (byte) value };
        } else if (bytes == 1 && revers) {
            return new byte[] { (byte) (value >>> 24) };
        } else if (bytes == 2 && !revers) {
            return new byte[] { (byte) (value >>> 8), (byte) value };
        } else if (bytes == 2 && revers) {
            return new byte[] { (byte) (value >>> 24),
                    (byte) (value >>> 16) };
        } else if (bytes == 3 && !revers) {
            return new byte[] { (byte) (value >>> 16),
                    (byte) (value >>> 8), (byte) value };
        } else if (bytes == 3 && revers) {
            return new byte[] { (byte) (value >>> 24),
                    (byte) (value >>> 16), (byte) (value >>> 8) };
        } else {//www.j a  v a2 s  .c o m
            return new byte[] { (byte) (value >>> 24),
                    (byte) (value >>> 16), (byte) (value >>> 8),
                    (byte) value };
        }
    } 
}
