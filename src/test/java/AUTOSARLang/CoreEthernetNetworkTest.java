package AUTOSARLang;

import org.junit.Test;
import org.junit.After;

import auto.*;
import core.*;
public class CoreEthernetNetworkTest {  
    
    @Test
    public void testEthernetNetworkConditionally(){
        
        boolean sARP, idps, limitNewMACAddress, msgAuthenticated;
        System.out.println("=> An attacker having EthNet.physicalAccess, where sARP=?, idps=?, limitNewMACAddress=?, msgAuthenticated=?:");
    
        for(int i=0; i<8; i++){
            
            msgAuthenticated = (i%2!=0);
            limitNewMACAddress = ((i/2)%2!=0);
            idps = ((i/4)%2!=0);
            sARP = ((i/8)%2!=0);
            
            EthernetNetwork eth = new EthernetNetwork("EthernetNetwork", sARP, idps, limitNewMACAddress, msgAuthenticated);
            
            Attacker attacker = new Attacker();
            attacker.addAttackPoint(eth.physicalAccess);
            attacker.attack();
            
            System.out.println("=> ("+sARP+", "+idps+", "+limitNewMACAddress+", "+msgAuthenticated+")");
            
            if(sARP)
                eth.arpCachePoisoning.assertUncompromised();
            else
                eth.arpCachePoisoning.assertCompromisedInstantaneously();
            
            if(idps)
                eth.macSpoofing.assertUncompromised();
            else
                eth.macSpoofing.assertCompromisedInstantaneously();  
            
            if(limitNewMACAddress)
                eth.unauthorizedNetworkExpansion.assertUncompromised();
            else
                eth.unauthorizedNetworkExpansion.assertCompromisedInstantaneously();
            
            if(msgAuthenticated)
                eth.impersonation.assertUncompromised();
            else
                eth.impersonation.assertCompromisedInstantaneously();
            System.out.println();
        }      
        System.out.println("-_-_-_-_-_-_-_-_-_-_-_-_-_-_-");
    }
    
    @Test
    public void testECUConnect(){
        EthernetNetwork eth = new EthernetNetwork("EthernetNetwork");
        ECU ecu = new ECU("ECU");
        eth.addNetworkedEcus(ecu);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(eth.access);
        attacker.addAttackPoint(eth.switchAccess);
        attacker.attack();
        
        System.out.println("=> An attacker having EthNet.switchAccess or EthNet.access,");
        ecu.connect.assertCompromisedInstantaneously();
        ecu.attemptChangeOperationMode.assertCompromisedWithEffort();
        System.out.println();
    }
    
    @Test
    public void testSwitchAttacks(){
        EthernetNetwork eth = new EthernetNetwork("EthernetNetwork");
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(eth.switchAccess);
        attacker.attack();
        
        System.out.println("=> An attacker having EthNet.switchAccess,");
        eth.overwriteSwitchMACTable.assertCompromisedInstantaneously();
        eth.resetSwitchPassword.assertCompromisedInstantaneously();
        eth.macFlooding.assertCompromisedInstantaneously();
        eth.denialOfService.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testAccountCompromiseViaNetworkService(){
        EthernetNetwork eth = new EthernetNetwork("EthernetNetwork");
        NetworkService nservice = new NetworkService("NetworkService");
        Account account = new Account("Account");
        
        nservice.addAccounts(account);
        eth.addService(nservice);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(eth.access);
        attacker.attack();
        
        System.out.println("=> An attacker having EthNet.access,");
        account.compromise.assertUncompromised(); //??
        System.out.println();
    }
    
    @Test
    public void testVulnExploitViaNetworkService(){
        EthernetNetwork eth = new EthernetNetwork("EthernetNetwork");
        NetworkService nservice = new NetworkService("NetworkService");
        Vulnerability vuln = new Vulnerability("Vulnerability");
        
        nservice.addAccessVulnerabilities(vuln);
        eth.addService(nservice);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(eth.access);
        attacker.attack();
        
        System.out.println("=> An attacker having EthNet.access,");
        vuln.exploit.assertUncompromised(); //??
        System.out.println();
    }
    
    @Test
    public void testNetworkServiceConnect(){
        EthernetNetwork eth = new EthernetNetwork("EthernetNetwork");
        NetworkService nservice = new NetworkService("NetworkService");
        eth.addService(nservice);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(eth.access);
        attacker.attack();
        
        System.out.println("=> An attacker having EthNet.access,");
        nservice.connect.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testDataRWDViaDataflow(){
        EthernetNetwork eth = new EthernetNetwork("EthernetNetwork");
        Dataflow dataflow = new Dataflow("Dataflow");
        Data data = new Data("Data");
        
        dataflow.addData(data);
        eth.addDataflows(dataflow);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(eth.manInTheMiddle);
        attacker.attack();
        
        System.out.println("=> An attacker having EthNet.manInTheMiddle,");
        data.read.assertCompromisedInstantaneously();
        data.write.assertCompromisedInstantaneously();
        data.delete.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testDataflowAttacks(){
        EthernetNetwork eth = new EthernetNetwork("EthernetNetwork");
        Dataflow dataflow = new Dataflow("Dataflow");
        eth.addDataflows(dataflow);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(eth.access);
        attacker.addAttackPoint(eth.manInTheMiddle);
        attacker.attack();
        
        System.out.println("=> An attacker having EthNet.access or EthNet.manInTheMiddle,");
        dataflow.denialOfService.assertCompromisedInstantaneously();
        dataflow.manInTheMiddle.assertCompromisedInstantaneously();
        dataflow.eavesdrop.assertCompromisedInstantaneously();
        dataflow.request.assertCompromisedInstantaneously();
        dataflow.respond.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testRouterAttacks(){
        EthernetNetwork eth = new EthernetNetwork("EthernetNetwork");
        Router router = new Router("Router");
        eth.addTrafficRouters(router);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(eth.access);
        attacker.addAttackPoint(eth.manInTheMiddle);
        attacker.attack();
        
        System.out.println("=> An attacker having EthNet.access or EthNet.manInTheMiddle,");
        router.forwarding.assertCompromisedInstantaneously();
        router.denialOfService.assertCompromisedInstantaneously();
        router.connect.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testEthernetNetworkAttacks2(){
        EthernetNetwork eth = new EthernetNetwork("EthernetNetwork");
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(eth.shutdown);
        attacker.attack();
        
        System.out.println("=> An attacker having EthNet.shutdown,");
        eth.denialOfService.assertCompromisedInstantaneously();
        System.out.println();
    } 
    
    @Test
    public void testEthernetNetworkAttacks(){
        EthernetNetwork eth = new EthernetNetwork("EthernetNetwork");
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(eth.physicalAccess);
        attacker.attack();
        
        System.out.println("=> An attacker having EthNet.physicalAccess,");
        eth.denialOfService.assertCompromisedInstantaneously();
        eth.access.assertCompromisedInstantaneously();
        eth.unauthorizedNetworkExpansion.assertCompromisedInstantaneously();
        eth.resetSwitchPassword.assertCompromisedInstantaneously();
        eth.manInTheMiddle.assertCompromisedInstantaneously();
        eth.trafficInjection.assertCompromisedInstantaneously();
        eth.arpCachePoisoning.assertCompromisedInstantaneously();
        eth.macSpoofing.assertCompromisedInstantaneously();
        eth.dhcpSpoofing.assertCompromisedInstantaneously();
        eth.macFlooding.assertCompromisedInstantaneously();
        eth.eavesdrop.assertCompromisedInstantaneously();
        eth.sessionHijacking.assertCompromisedInstantaneously();
        eth.replay.assertCompromisedInstantaneously();
        eth.impersonation.assertCompromisedInstantaneously();
        eth.switchAccess.assertCompromisedInstantaneously();
        eth.overwriteSwitchMACTable.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @After
    public void deleteModel() {
        Asset.allAssets.clear();
        AttackStep.allAttackSteps.clear();
        Defense.allDefenses.clear();
    }
}