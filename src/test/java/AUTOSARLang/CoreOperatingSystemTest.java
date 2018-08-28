package AUTOSARLang;

import org.junit.Test;
import org.junit.After;

import auto.*;
import core.*;

public class CoreOperatingSystemTest {
    
   
    @Test
    public void testOSConditionally(){
        boolean pre, antiMalware;
        System.out.println("=> An attacker having OS.access, where PRE=?, AntiMalware=?:");
    
        for(int i=0; i<4; i++){
            
            antiMalware = (i%2!=0);
            pre = (i/2!=0);
            
            OperatingSystem operatingSystem = new OperatingSystem("OperatingSystem", pre, antiMalware);
            
            Attacker attacker = new Attacker();
            attacker.addAttackPoint(operatingSystem.access);
            attacker.attack();

            System.out.println("=> ("+pre+", "+antiMalware+")");
            
            if(pre)
                operatingSystem.memoryCorruption.assertUncompromised();
            else
                ;//operatingSystem.memoryCorruption.assertCompromisedInstantaneously();
            
            if(antiMalware)
                operatingSystem.malware.assertUncompromised();
            else
                operatingSystem.malware.assertCompromisedInstantaneously();

            System.out.println();
        }      
    } 

    @Test
    public void testAdaptiveMachineDoS(){
        OperatingSystem operatingSystem = new OperatingSystem("OperatingSystem");
        AdaptiveMachine am = new AdaptiveMachine("AdaptiveMachine");
        operatingSystem.addAdaptiveMachine(am);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(operatingSystem.access);
        attacker.attack();
        
        System.out.println("An attacker having OS.access via OS.DoS,");
        am.denialOfService.assertCompromisedInstantaneously();
        System.out.println();
    }

    @Test
    public void testAdaptivePlatformDoS(){
        OperatingSystem operatingSystem = new OperatingSystem("OperatingSystem");
        AdaptivePlatform ap = new AdaptivePlatform("AdaptivePlatform");
        operatingSystem.addApInstance(ap);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(operatingSystem.access);
        attacker.attack();
        
        System.out.println("An attacker having OS.access via OS.DoS,");
        ap.denialOfService.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testAccountCompromise(){
        OperatingSystem operatingSystem = new OperatingSystem("OperatingSystem");
        Account account = new Account("Account");
        operatingSystem.addAccounts(account);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(operatingSystem.access);
        attacker.attack();
        
        System.out.println("An attacker having OS.access,");
        account.compromise.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testInformationRead(){
        OperatingSystem operatingSystem = new OperatingSystem("OperatingSystem");
        Information info = new Information("Information");
        operatingSystem.addInformation(info);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(operatingSystem.access);
        attacker.attack();
        
        System.out.println("An attacker having OS.access via OS.informationLeak,");
        info.read.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testInformationWRD(){
        OperatingSystem operatingSystem = new OperatingSystem("OperatingSystem");
        Information info = new Information("Information");
        Data data = new Data("Data");
        data.addInformation(info);
        operatingSystem.addData(data);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(operatingSystem.access);
        attacker.attack();
        
        System.out.println("An attacker having OS.access via Data.RWD,");
        info.read.assertCompromisedInstantaneously();
        info.write.assertCompromisedInstantaneously();
        info.delete.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testDataRWD(){
        OperatingSystem operatingSystem = new OperatingSystem("OperatingSystem");
        Data data = new Data("Data");
        operatingSystem.addData(data);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(operatingSystem.access);
        attacker.attack();
        
        System.out.println("An attacker having OS.access via OS.dataInjection and OS.DoS,");
        data.read.assertCompromisedInstantaneously();
        data.write.assertCompromisedInstantaneously();
        data.delete.assertCompromisedInstantaneously();
        data.denyAccess.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testOperatingSystemAttacks(){
        OperatingSystem operatingSystem = new OperatingSystem("OperatingSystem");
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(operatingSystem.access);
        attacker.attack();
        
        System.out.println("An attacker having OS.access,");
        operatingSystem._adaptivePlatformAccess.assertCompromisedInstantaneously();
        operatingSystem.denialOfService.assertCompromisedInstantaneously();
        operatingSystem.dataInjection.assertCompromisedInstantaneously();
        operatingSystem.memoryCorruption.assertCompromisedInstantaneously();
        operatingSystem.malware.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testOperatingSystemAccess2(){
        OperatingSystem operatingSystem = new OperatingSystem("OperatingSystem");
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(operatingSystem.bypassAccessControl);
        attacker.attack();
        
        
        System.out.println("=> An attacker having OS.bypassAccessControl,");
        operatingSystem.access.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @Test
    public void testOperatingSystemAccess(){
        OperatingSystem operatingSystem = new OperatingSystem("OperatingSystem");
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(operatingSystem.connect);
        attacker.addAttackPoint(operatingSystem.authenticate);
        attacker.attack();
        
        System.out.println("=> An attacker having OS.connect and OS.authenticate,");
        operatingSystem.access.assertCompromisedInstantaneously();
        System.out.println();
    }
    
    @After
    public void deleteModel() {
        Asset.allAssets.clear();
        AttackStep.allAttackSteps.clear();
        Defense.allDefenses.clear();
    }
}