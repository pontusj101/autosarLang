package AUTOSARLang;

import org.junit.Test;
import org.junit.After;

import auto.*;
import core.*;

public class CoreBusNetworkTest {

    @Test
    public void testAccountCompromiseViaNetworkService(){
        BusNetwork bus = new BusNetwork("BusNetwork");
        NetworkService nservice = new NetworkService("NetworkService");
        Account account = new Account("Account");
        
        nservice.addAccounts(account);
        bus.addService(nservice);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(bus.access);
        attacker.attack();
        
        System.out.println("=> An attacker having BusNet.access,");
        account.compromise.assertUncompromised(); //??
        System.out.println();
    }
    
    @Test
    public void testVulnExploitViaNetworkService(){
        BusNetwork bus = new BusNetwork("BusNetwork");
        NetworkService nservice = new NetworkService("NetworkService");
        Vulnerability vuln = new Vulnerability("Vulnerability");
        
        nservice.addAccessVulnerabilities(vuln);
        bus.addService(nservice);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(bus.access);
        attacker.attack();
        
        System.out.println("=> An attacker having BusNet.access,");
        vuln.exploit.assertUncompromised(); //??
        System.out.println();
    }
    
    @Test
    public void testNetworkServiceConnect(){
        BusNetwork bus = new BusNetwork("BusNetwork");
        NetworkService nservice = new NetworkService("NetworkService");
        bus.addService(nservice);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(bus.access);
        attacker.attack();
        
        System.out.println("=> An attacker having BusNet.access,");
        nservice.connect.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testDataRWDViaDataflow(){
        BusNetwork bus = new BusNetwork("BusNetwork");
        Dataflow dataflow = new Dataflow("Dataflow");
        Data data = new Data("Data");
        
        dataflow.addData(data);
        bus.addDataflows(dataflow);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(bus.manInTheMiddle);
        attacker.attack();
        
        System.out.println("=> An attacker having BusNet.manInTheMiddle,");
        data.read.assertCompromisedInstantaneously();
        data.write.assertCompromisedInstantaneously();
        data.delete.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testDataflowAttacks(){
        BusNetwork bus = new BusNetwork("BusNetwork");
        Dataflow dataflow = new Dataflow("Dataflow");
        bus.addDataflows(dataflow);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(bus.access);
        attacker.addAttackPoint(bus.manInTheMiddle);
        attacker.attack();
        
        System.out.println("=> An attacker having BusNet.access or BusNet.manInTheMiddle,");
        dataflow.denialOfService.assertCompromisedInstantaneously();
        dataflow.manInTheMiddle.assertCompromisedInstantaneously();
        dataflow.eavesdrop.assertCompromisedInstantaneously();
        dataflow.request.assertCompromisedInstantaneously();
        dataflow.respond.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testRouterAttacks(){
        BusNetwork bus = new BusNetwork("BusNetwork");
        Router router = new Router("Router");
        bus.addTrafficRouters(router);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(bus.access);
        attacker.addAttackPoint(bus.manInTheMiddle);
        attacker.attack();
        
        System.out.println("=> An attacker having BusNet.access or BusNet.manInTheMiddle,");
        router.forwarding.assertCompromisedInstantaneously();
        router.denialOfService.assertCompromisedInstantaneously();
        router.connect.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testECUBatteryDrain(){
        BusNetwork bus = new BusNetwork("BusNetwork");
        ECU ecu = new ECU("ECU");
        bus.addBusNetworkedEcus(ecu);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(bus.wakeUpMessageInjection);
        attacker.attack();
        
        System.out.println("=> An attacker having BusNet.wakeUpMessageInjection,");
        ecu.batteryDrain.assertCompromisedInstantaneously();
        ecu.vehicleImmobilization.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testECUConnect(){
        BusNetwork bus = new BusNetwork("BusNetwork");
        ECU ecu = new ECU("ECU");
        bus.addNetworkedEcus(ecu);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(bus.access);
        attacker.attack();
        
        System.out.println("=> An attacker having BusNet.access,");
        ecu._adaptiveMachineAccess.assertCompromisedInstantaneously();
        ecu.connect.assertCompromisedInstantaneously();
        ecu.attemptChangeOperationMode.assertCompromisedWithEffort();
        System.out.println();
    }
    
    @Test
    public void testBusNetworkAttacks2(){
        BusNetwork bus = new BusNetwork("BusNetwork");
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(bus.access);
        attacker.attack();
        
        System.out.println("=> An attacker having BusNet.access,");
        bus.denialOfService.assertCompromisedInstantaneously();
        bus.trafficInjection.assertCompromisedInstantaneously();
        bus.wakeUpMessageInjection.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testBusNetworkAttacks(){
        BusNetwork bus = new BusNetwork("BusNetwork");
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(bus.physicalAccess);
        attacker.attack();
        
        System.out.println("=> An attacker having BusNet.physicalAccess,");
        bus.access.assertCompromisedInstantaneously();
        bus.denialOfService.assertCompromisedInstantaneously();
        bus.eavesdrop.assertCompromisedInstantaneously();
        bus.trafficInjection.assertCompromisedInstantaneously();
        bus.wakeUpMessageInjection.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @After
    public void deleteModel() {
        Asset.allAssets.clear();
        AttackStep.allAttackSteps.clear();
        Defense.allDefenses.clear();
    }
}
