package AUTOSARLang;

import org.junit.Test;
import org.junit.After;

import auto.*;
import core.*;
public class CoreEcuTest {

    /*
        [ECU] --> requestAccess --> [Data]
          |                                             
        access - [Attacker] 
    */  
    @Test
    public void testDataRequestAccess(){
        ECU ecu = new ECU("ECU");
        Data data = new Data("Data");
        ecu.addData(data);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(ecu.access);
        attacker.attack();
        
        System.out.println("=> An attacker having ECU.access,");
        data.requestAccess.assertCompromisedInstantaneously();
        
        //Uncompromised as expected
        data.authenticatedRead.assertUncompromised();
        data.authenticatedWrite.assertUncompromised();
        data.authenticatedDelete.assertUncompromised();
        System.out.println();
    }

    /*
        [ECU] --> exploit --> [Vulnerability] --> compromise --> [Account]
          |                                                          |
        access - [Attacker]            [Machine] <-- authenticate X<--
    */  
    @Test
    public void testMachineAuthenticationViaVulnThenAccount(){
        ECU ecu = new ECU("ECU");
        Account account = new Account("Account");
        Vulnerability vuln = new Vulnerability("Vulnerability");
        Machine machine = new Machine("Machine");
        
        account.addConnectMachines(machine);
        
        vuln.addPrivileges(account);
        ecu.addAccessVulnerabilities(vuln);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(ecu.access);
        attacker.attack();
        
        System.out.println("=> An attacker having ECU.access,");
        vuln.exploit.assertCompromisedWithEffort();
        account.compromise.assertCompromisedWithEffort();
        machine.authenticate.assertUncompromised(); //??
        System.out.println();
    }

    /*
        [ECU] --> exploit --> [Vulnerability] --> compromise --> [Account]
          |                                                         |
        access - [Attacker]        [Data] <-- anyAccountRead/authenticatedWrite/authenticatedDelete
    */   
    @Test
    public void testDataAnyAccountRWDViaVulnThenAccount(){
        ECU ecu = new ECU("ECU");
        Account account = new Account("Account");
        Vulnerability vuln = new Vulnerability("Vulnerability");
        Data data = new Data("Data");
        
        account.addReadData(data);
        account.addWrittenData(data);
        account.addDeletedData(data);
        
        vuln.addPrivileges(account);
        ecu.addAccessVulnerabilities(vuln);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(ecu.access);
        attacker.attack();
        
        System.out.println("=> An attacker having ECU.access,");
        vuln.exploit.assertCompromisedWithEffort();
        account.compromise.assertCompromisedWithEffort();
        data.anyAccountRead.assertCompromisedWithEffort();
        data.anyAccountWrite.assertCompromisedWithEffort();
        data.anyAccountDelete.assertCompromisedWithEffort();
        
        //Uncompromised attack steps
        data.authenticatedRead.assertUncompromised();
        data.authenticatedWrite.assertUncompromised();
        data.authenticatedDelete.assertUncompromised();
        data.read.assertUncompromised();
        data.write.assertUncompromised();
        data.delete.assertUncompromised();
        System.out.println();
    }

    /*
        [ECU] --> exploit --> [Vulnerability] --> compromise --> [Account]
          |                                                         |
        access - [Attacker]                       [Account] <-- compromise
    */      
    @Test
    public void testAccountCompromiseViaVulnThenAccount(){
        ECU ecu = new ECU("ECU");
        Account account = new Account("Account");
        Account account1 = new Account("Account1");
        Vulnerability vuln = new Vulnerability("Vulnerability");
        
        account.addAuthenticatees(account1);
        vuln.addPrivileges(account);
        ecu.addAccessVulnerabilities(vuln);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(ecu.access);
        attacker.attack();
        
        System.out.println("=> An attacker having ECU.access,");
        vuln.exploit.assertCompromisedWithEffort();
        account.compromise.assertCompromisedWithEffort();
        account1.compromise.assertCompromisedWithEffort(); 
        System.out.println();
    }

    /*
        [ECU] -->X compromise --> [Account]
          |     
        connect/access - [Attacker] 
    */    
    @Test
    public void testAccountCompromise(){
        ECU ecu = new ECU("ECU");
        Account account = new Account("Account");
        ecu.addAccounts(account);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(ecu.connect);
        attacker.addAttackPoint(ecu.access);
        attacker.attack();
        
        System.out.println("=> An attacker having ECU.access or ECU.connect,");
        account.compromise.assertUncompromised();//??
        System.out.println();
    }

    /*
        [ECU] --> exploit --> [Vulnerability]
          |     
        access - [Attacker] 
    */
    @Test
    public void testVulnerabilityExploit(){
        ECU ecu = new ECU("ECU");
        Vulnerability vuln = new Vulnerability("Vulnerability");
        ecu.addAccessVulnerabilities(vuln);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(ecu.access);
        attacker.attack();
        
        System.out.println("=> An attacker having ECU.access,");
        vuln.exploit.assertCompromisedWithEffort();
        System.out.println();
    }
    
    /*
        [ECU] --> denialOfService --> [Software] --> denyAccess --> [Data]
          |     
        denialOfService - [Attacker] 
    */
    @Test
    public void testDataDenyAccessViaSoftwareDoS(){
        ECU ecu = new ECU("ECU");
        AdaptivePlatform ap = new AdaptivePlatform("AdaptivePlatform");
        Data data = new Data("Data");
        ap.addData(data);
        ecu.addAdaptivePlatform(ap);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(ecu.denialOfService);
        attacker.attack();
        
        System.out.println("An attacker having ECU.denialOfService,");
        ap.denialOfService.assertCompromisedInstantaneously();
        data.denyAccess.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    /*
        [ECU] --> denialOfService --> [AdaptivePlatform]
          |     
        denialOfService - [Attacker] 
    */
    @Test
    public void testSoftwareDoS(){
        ECU ecu = new ECU("ECU");
        AdaptivePlatform ap = new AdaptivePlatform("AdaptivePlatform");
        ecu.addAdaptivePlatform(ap);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(ecu.denialOfService);
        attacker.attack();
        
        System.out.println("An attacker having ECU.denialOfService,");
        ap.denialOfService.assertCompromisedInstantaneously();
        System.out.println();
    }

    /*
        [ECU] --> connect --> [Software]
          |     
        access - [Attacker] 
    */
    @Test
    public void testSoftwareConnect(){
        ECU ecu = new ECU("ECU");
        Software software = new Software("Software");
        ecu.addExecutees(software);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(ecu.access);
        attacker.attack();
        
        System.out.println("An attacker having ECU.access,");
        software.connect.assertCompromisedInstantaneously();
        System.out.println();
    }

    /*
        [ECU] --> denyAccess --> [Data]
          |     
        denialOfService - [Attacker] 
    */
    @Test
    public void testDataDenyAccess(){
        ECU ecu = new ECU("ECU");
        Data data = new Data("Data");
        ecu.addData(data);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(ecu.denialOfService);
        attacker.attack();
        
        System.out.println("An attacker having ECU.denialOfService,");
        data.denyAccess.assertCompromisedInstantaneously();
        System.out.println();
    }

    /*
        [ECU] --> DoS --> [BusNetwork] --> DoS--> [Dataflow]
          |                                               | 
        access                              [Data] <-- delete
          |                                    |   
       [Attacker]                            delete --> [Data]
    */
    @Test
    public void testDataDeleteViaBusNetDoSThenDataflowDoSThenDataDelete(){
        ECU ecu = new ECU("ECU");
        BusNetwork bus = new BusNetwork("BusNetwork");
        Dataflow dataflow = new Dataflow("Dataflow");
        Data data = new Data("Data");
        Data data1 = new Data("Data1");
        data.addContainedData(data1);
        dataflow.addData(data);
        bus.addDataflows(dataflow);
        ecu.addBusNetwork(bus);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(ecu.access);
        attacker.attack();
        
        System.out.println("An attacker having ECU.access,");
        bus.denialOfService.assertCompromisedInstantaneously();
        dataflow.denialOfService.assertCompromisedInstantaneously();
        data.delete.assertCompromisedInstantaneously();
        data1.delete.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    /*
        [ECU] --> DoS --> [BusNetwork] --> DoS--> [Dataflow]
          |                                               | 
        access                              [Data] <-- delete
          |
       [Attacker] 
    */
    @Test
    public void testDataDeleteViaBusNetDoSThenDataflowDoS(){
        ECU ecu = new ECU("ECU");
        BusNetwork bus = new BusNetwork("BusNetwork");
        Dataflow dataflow = new Dataflow("Dataflow");
        Data data = new Data("Data");
        dataflow.addData(data);
        bus.addDataflows(dataflow);
        ecu.addBusNetwork(bus);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(ecu.access);
        attacker.attack();
        
        System.out.println("An attacker having ECU.access,");
        bus.denialOfService.assertCompromisedInstantaneously();
        dataflow.denialOfService.assertCompromisedInstantaneously();
        data.delete.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    /*
        [ECU] --> DoS --> [BusNetwork] --> DoS--> [Dataflow]
          |
        access - [Attacker]
    */
    @Test
    public void testDataflowDoSViaBusNetDoS(){
        ECU ecu = new ECU("ECU");
        BusNetwork bus = new BusNetwork("BusNetwork");
        Dataflow dataflow = new Dataflow("Dataflow");
        bus.addDataflows(dataflow);
        ecu.addBusNetwork(bus);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(ecu.access);
        attacker.attack();
        
        System.out.println("An attacker having ECU.access,");
        bus.denialOfService.assertCompromisedInstantaneously();
        dataflow.denialOfService.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    /*
        [ECU] --> DoS --> [BusNetwork]
          |
        access - [Attacker]
    */
    @Test
    public void testBusNetAttacks(){
        ECU ecu = new ECU("ECU");
        BusNetwork bus = new BusNetwork("BusNetwork");
        ecu.addBusNetwork(bus);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(ecu.access);
        attacker.addAttackPoint(ecu.maliciousFirmwareUpload);
        attacker.attack();
        
        System.out.println("An attacker having ECU.access,");
        bus.denialOfService.assertCompromisedInstantaneously();
        bus.trafficInjection.assertCompromisedInstantaneously();
        System.out.println();
    }

    /*
        [Attacker]
          |
          connect --> [ECU] 
    */
    @Test
    public void testECUAttacksFromConnect(){
        ECU ecu = new ECU("ECU");
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(ecu.connect);
        attacker.attack();
        
        System.out.println("An attacker having ECU.connect,");
        ecu._adaptiveMachineAccess.assertCompromisedInstantaneously();
        ecu.attemptChangeOperationMode.assertCompromisedWithEffort();
        ecu.bypassMessageConfliction.assertCompromisedWithEffort();
        System.out.println();
    }
    
    @Test
    public void testECUAttacksFromAccess(){
        ECU ecu = new ECU("ECU");
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(ecu.access);
        attacker.attack();
        
        System.out.println("An attacker having ECU.access,");
        ecu._adaptiveMachineAccess.assertCompromisedInstantaneously();
        ecu.changeOperationMode.assertCompromisedInstantaneously();
        ecu.uploadFirmware.assertUncompromised();
        ecu.bypassMessageConfliction.assertCompromisedInstantaneously();
        ecu.injectWakeUpFunction.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testECUAccess(){
        ECU ecu = new ECU("ECU");
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(ecu.bypassAccessControl);
        attacker.attack();
        
        System.out.println("=> An attacker having ECU.bypassAccessControl,");
        ecu.access.assertCompromisedInstantaneously();
        System.out.println();
    }

    
    @After
    public void deleteModel() {
        Asset.allAssets.clear();
        AttackStep.allAttackSteps.clear();
        Defense.allDefenses.clear();
    }
}