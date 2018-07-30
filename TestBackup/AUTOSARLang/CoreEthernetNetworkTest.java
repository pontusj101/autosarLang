package AUTOSARLang;

import org.junit.Test;
import org.junit.After;

import auto.*;
import core.*;
public class CoreEthernetNetworkTest {
    
    @Test
    public void testEthernetNetworkConditionally(){
        
        boolean sARP, idps, limitNewMACAddress;
        System.out.println("=> An attacker having EthNet.physicalAccess, where sARP=?, idps=?, limitNewMACAddress=?:");
    
        for(int i=0; i<8; i++){
            
            limitNewMACAddress = (i%2!=0);
            idps = ((i/2)%2!=0);
            sARP = ((i/4)%2!=0);
            
            EthernetNetwork eth = new EthernetNetwork("EthernetNetwork", sARP, idps, limitNewMACAddress);
            
            Attacker attacker = new Attacker();
            attacker.addAttackPoint(eth.physicalAccess);
            attacker.attack();
            
            System.out.println("=> ("+sARP+", "+idps+", "+limitNewMACAddress+")");
            
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
            System.out.println();
        }      
        System.out.println("-_-_-_-_-_-_-_-_-_-_-_-_-_-_-");
    }
    
    @Test
    public void testECUConnectViaEthSwitch(){
        EthernetNetwork eth = new EthernetNetwork("EthernetNetwork");
        EthernetSwitch ethernetSwitch = new EthernetSwitch("EthernetSwitch");
        ECU ecu = new ECU("ECU");
        OperatingSystem operatingSystem = new OperatingSystem("OperatingSystem");
        IAM iam = new IAM("IAM");
        operatingSystem.addIamProgram(iam);
        ecu.addOs(operatingSystem);
        
        ethernetSwitch.addConnectedEcus(ecu);
        eth.addEthernetSwitchs(ethernetSwitch);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(eth.physicalAccess);
        attacker.attack();
        
        System.out.println("=> An attacker having EthNet.physicalAccess,");
        ecu.connect.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testSwitchAttacks(){
        EthernetNetwork eth = new EthernetNetwork("EthernetNetwork");
        EthernetSwitch ethernetSwitch = new EthernetSwitch("EthernetSwitch");
        
        eth.addEthernetSwitchs(ethernetSwitch);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(eth.physicalAccess);
        attacker.attack();
        
        System.out.println("=> An attacker having EthNet.physicalAccess,");
        eth.access.assertCompromisedInstantaneously();
        ethernetSwitch.resetPassword.assertCompromisedInstantaneously();
        ethernetSwitch.macFlooding.assertCompromisedInstantaneously();
        ethernetSwitch.overwriteMACTable.assertCompromisedInstantaneously();
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
    public void testECUConnect(){
        EthernetNetwork eth = new EthernetNetwork("EthernetNetwork");
        ECU ecu = new ECU("ECU");
        eth.addNetworkedEcus(ecu);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(eth.access);
        attacker.attack();
        
        System.out.println("=> An attacker having EthNet.access,");
        ecu._machineConnect.assertCompromisedInstantaneously();
        ecu.connect.assertCompromisedInstantaneously();
        ecu.attemptChangeOperationMode.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testEthernetNetworkAttacks2(){
        EthernetNetwork eth = new EthernetNetwork("EthernetNetwork");
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(eth.access);
        attacker.attack();
        
        System.out.println("=> An attacker having EthNet.physicalAccess,");
        eth.denialOfService.assertCompromisedInstantaneously();
        eth.trafficInjection.assertCompromisedInstantaneously();
        eth.arpCachePoisoning.assertCompromisedInstantaneously();
        eth.macSpoofing.assertCompromisedInstantaneously();
        eth.dhcpSpoofing.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testEthernetNetworkAttacks(){
        EthernetNetwork eth = new EthernetNetwork("EthernetNetwork");
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(eth.physicalAccess);
        attacker.attack();
        
        System.out.println("=> An attacker having EthNet.physicalAccess,");
        eth.access.assertCompromisedInstantaneously();
        eth.denialOfService.assertCompromisedInstantaneously();
        eth.eavesdrop.assertCompromisedInstantaneously();
        eth.trafficInjection.assertCompromisedInstantaneously();
        eth.arpCachePoisoning.assertCompromisedInstantaneously();
        eth.macSpoofing.assertCompromisedInstantaneously();
        eth.dhcpSpoofing.assertCompromisedInstantaneously();
        eth.sessionHijacking.assertCompromisedInstantaneously();
        eth.replay.assertCompromisedInstantaneously();
        eth.impersonation.assertCompromisedInstantaneously();
        eth.unauthorizedNetworkExpansion.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @After
    public void deleteModel() {
        Asset.allAssets.clear();
        AttackStep.allAttackSteps.clear();
        Defense.allDefenses.clear();
    }
}
