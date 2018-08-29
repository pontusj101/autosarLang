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
    
    
    
    
    @After
    public void deleteModel() {
        Asset.allAssets.clear();
        AttackStep.allAttackSteps.clear();
        Defense.allDefenses.clear();
    }
}
