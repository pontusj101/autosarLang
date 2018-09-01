package AUTOSARLang;

import org.junit.Test;
import org.junit.After;

import auto.*;
import core.*;
public class AUTOSARLangTest {
    
        /*
                             [Bus]---[ECU4]
                             |
                             |
        [ECU1]---[ETH]----[Router]----[ETH]----[ECU2]
                             |
                             |
                             [Bus]---[ECU3]
    */  
    @Test
    public void testInVehicleNetworks(){
        ECU intelligentECU1 = new ECU("IntelligentECU1");
        ECU intelligentECU2 = new ECU("IntelligentECU2");
        ECU embeddedECU1 = new ECU("EmbeddedECU1");
        ECU embeddedECU2 = new ECU("EmbeddedECU2");
        
        BusNetwork busNet1 = new BusNetwork("BusNetwork1");
        BusNetwork busNet2 = new BusNetwork("BusNetwork2");
        EthernetNetwork ethNet1 = new EthernetNetwork("EthernetNetwork1");
        EthernetNetwork ethNet2 = new EthernetNetwork("EthernetNetwork2");
        Router router = new Router("Router");
        
        Dataflow dataflow = new Dataflow("Dataflow");
        
        ethNet1.addDataflows(dataflow);
        ethNet2.addDataflows(dataflow);
        busNet1.addDataflows(dataflow);
        busNet2.addDataflows(dataflow);
        router.addDataflows(dataflow);
        
        ethNet1.addNetworkedEcus(intelligentECU1);
        ethNet2.addNetworkedEcus(intelligentECU2);
        busNet1.addBusNetworkedEcus(embeddedECU1);
        busNet2.addBusNetworkedEcus(embeddedECU2);
        
        ethNet1.addTrafficRouters(router);
        ethNet2.addTrafficRouters(router);
        busNet1.addTrafficRouters(router);
        busNet2.addTrafficRouters(router);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(router.access);
        attacker.addAttackPoint(embeddedECU1.maliciousFirmwareUpload);
        attacker.attack();
        
        System.out.println("=> An attacker having Router.access or ECU.maliciousFirmwareUpload,");
        busNet1.manInTheMiddle.assertCompromisedInstantaneously();
        busNet2.manInTheMiddle.assertCompromisedInstantaneously();
        ethNet1.manInTheMiddle.assertCompromisedInstantaneously();
        ethNet2.manInTheMiddle.assertCompromisedInstantaneously();
        dataflow.manInTheMiddle.assertCompromisedInstantaneously();
        
        busNet1.trafficInjection.assertCompromisedInstantaneously();
        busNet2.wakeUpMessageInjection.assertCompromisedInstantaneously();
        embeddedECU1.batteryDrain.assertCompromisedInstantaneously();
        embeddedECU2.batteryDrain.assertCompromisedInstantaneously();
        
        //assertUncompromised
        intelligentECU1.batteryDrain.assertUncompromised();
        intelligentECU2.batteryDrain.assertUncompromised();

        //data.authenticatedDelete.assertUncompromised();
        System.out.println();
    }   
     
    @Test
    public void testNetworkedAAsAttacks(){
        ECU intelligentECU1 = new ECU("IntelligentECU1");
        ECU intelligentECU2 = new ECU("IntelligentECU2");
        
        EthernetNetwork ethNet1 = new EthernetNetwork("EthernetNetwork1");
        EthernetNetwork ethNet2 = new EthernetNetwork("EthernetNetwork2");
        Router router = new Router("Router");
        //---
        AdaptiveApplication aa1 = new AdaptiveApplication("AA2");
        AdaptiveApplication aa2 = new AdaptiveApplication("AA2");
        ExecutionManagement em = new ExecutionManagement("EM");
        
        NetworkServiceAndClient cm1 = new NetworkServiceAndClient("CM1");
        NetworkServiceAndClient cm2 = new NetworkServiceAndClient("CM2");   
        
        Dataflow df1 = new Dataflow("Dataflow1");
        Dataflow df2 = new Dataflow("Dataflow2");
        
        //Requirements
        aa1.addEm(em);
        aa2.addEm(em);
        //---
        
        df1.addNsc(cm2);
        df2.addNsc(cm1);
        
        cm1.addDataflows(df1);
        cm2.addDataflows(df2);
        
        aa1.addCmClient(cm1);
        aa2.addCmClient(cm2);
        
        intelligentECU1.addAdaptivePlatform(aa1);
        intelligentECU2.addAdaptivePlatform(aa2);
           
        ethNet1.addDataflows(df1);
        ethNet1.addDataflows(df2);
        ethNet1.addNetworkedEcus(intelligentECU1);
        ethNet1.addTrafficRouters(router);

        ethNet2.addDataflows(df1);
        ethNet2.addDataflows(df2);
        ethNet2.addNetworkedEcus(intelligentECU2);
        ethNet2.addTrafficRouters(router);

        router.addDataflows(df1);
        router.addDataflows(df2);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(aa1.access);
        attacker.addAttackPoint(aa2.provideIllegitimateService);
        attacker.attack();
        
        System.out.println("=> An attacker having AA1.access,");
        aa1.requestService.assertCompromisedInstantaneously();
        cm1.access.assertCompromisedInstantaneously();
        df1.request.assertCompromisedInstantaneously();
        
        cm2.connect.assertCompromisedInstantaneously();
        System.out.println("CMs provides service from the service registry, thus,");
        cm2.access.assertCompromisedInstantaneously();
        df2.respond.assertCompromisedInstantaneously();
        cm1.connect.assertCompromisedInstantaneously();
        cm1.access.assertCompromisedInstantaneously();
        
        System.out.println("Other attacks:");
        cm1.denialOfService.assertCompromisedInstantaneously();
        cm2.denialOfService.assertCompromisedInstantaneously();
        df1.denialOfService.assertCompromisedInstantaneously();
        df2.denialOfService.assertCompromisedInstantaneously();

        System.out.println();
    }
    
    @Test
    public void testAttacksFromEthernetNetwork(){
        ECU intelligentECU1 = new ECU("IntelligentECU1");
        ECU intelligentECU2 = new ECU("IntelligentECU2");
        ECU intelligentECU3 = new ECU("IntelligentECU3");
        ECU intelligentECU4 = new ECU("IntelligentECU4");
        ECU intelligentECU5 = new ECU("IntelligentECU5");
        
        EthernetNetwork ethNet1 = new EthernetNetwork("EthernetNetwork1");
        EthernetNetwork ethNet2 = new EthernetNetwork("EthernetNetwork2");
        Router router = new Router("Router");
        
        Dataflow df = new Dataflow("Dataflow");
        NetworkService netService = new NetworkService("NetworkService");
        
        router.addDataflows(df);
        
        ethNet1.addNetworkedEcus(intelligentECU1);
        ethNet1.addNetworkedEcus(intelligentECU2);
        ethNet1.addNetworkedEcus(intelligentECU3);
        ethNet1.addNetworkedEcus(intelligentECU4);
        ethNet1.addTrafficRouters(router);
        ethNet1.addDataflows(df);
        ethNet1.addService(netService);

        ethNet2.addDataflows(df);
        ethNet2.addNetworkedEcus(intelligentECU5);
        ethNet2.addTrafficRouters(router);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(ethNet1.access);
        attacker.attack();
        
        System.out.println("=> An attacker having AA1.access,");
        intelligentECU1.connect.assertCompromisedInstantaneously();
        intelligentECU2.connect.assertCompromisedInstantaneously();
        intelligentECU3.connect.assertCompromisedInstantaneously();
        intelligentECU4.connect.assertCompromisedInstantaneously();
        
        router.forwarding.assertCompromisedInstantaneously();
        router.connect.assertCompromisedInstantaneously();
        intelligentECU5.connect.assertUncompromised();

        netService.connect.assertCompromisedInstantaneously();
        df.denialOfService.assertCompromisedInstantaneously();
        df.eavesdrop.assertCompromisedInstantaneously();
        df.manInTheMiddle.assertCompromisedInstantaneously();
        
        System.out.println();
    }
    
    @After
    public void deleteModel() {
        Asset.allAssets.clear();
        AttackStep.allAttackSteps.clear();
        Defense.allDefenses.clear();
    }
}
