#include "ConservationGuardianBot.hpp"

#include <iostream>

int main() {
    guardian::ConservationGuardianBot bot;
    std::string inventoryStatus;
    std::string inventoryLoadStatus;
    std::string inventoryPreview;
    std::string ownerProfileStatus;
    std::string ownerProfileLoadStatus;
    std::string ownerProfilePreview;
    std::string localKnowledgeStatus;
    std::string localKnowledgeLoadStatus;
    std::string localKnowledgePreview;
    std::string mapGeofenceStatus;
    std::string mapGeofenceLoadStatus;
    std::string mapGeofencePreview;
    std::string localProfileStatus;
    std::string localProfileLoadStatus;
    std::string localProfilePreview;
    std::string libraryStatus;
    std::string libraryLoadStatus;
    std::string libraryPreview;
    std::string dashboardStatus;
    std::string dashboardLoadStatus;
    std::string dashboardPreview;
    std::string privateStorageStatus;
    std::string privateStorageLoadStatus;
    std::string privateStoragePreview;

    guardian::SensorData idle;
    idle.ownerPresent = true;
    idle.familyPresent = true;
    idle.ownerPosition = {1.5, 0.0};
    idle.botPosition = {0.0, 0.0};
    idle.riskPosition = {6.0, 0.0};
    idle.terrain = guardian::TerrainType::Mixed;
    idle.peopleCount = 2;
    idle.locationDescription = "Base camp meadow near marked trail";

    bot.updateSensors(idle);
    bot.tick();

    guardian::SensorData environmentalCues = idle;
    environmentalCues.wildlifeActivityHigh = true;
    environmentalCues.wildlifeMovingTowardOwner = true;
    environmentalCues.wildlifeStressSigns = true;
    environmentalCues.thermalSignatureDetected = true;
    environmentalCues.infraredMotionDetected = true;
    environmentalCues.groupSeparated = true;
    environmentalCues.rapidWeatherShift = true;
    environmentalCues.visibilityReduced = true;
    environmentalCues.steepOrSlipperyTerrain = true;
    environmentalCues.riskPosition = {4.0, 1.5};

    bot.updateSensors(environmentalCues);
    bot.tick();

    guardian::SensorData smoke = idle;
    smoke.smokeDetected = true;
    smoke.windKph = 30.0;
    smoke.humidityPercent = 20.0;
    smoke.riskPosition = {3.0, -1.0};

    bot.updateSensors(smoke);
    bot.tick();

    guardian::SensorData medical = idle;
    medical.medicalRequest = true;
    medical.injurySeverity = guardian::InjurySeverity::Moderate;

    bot.updateSensors(medical);
    bot.tick();

    guardian::SensorData unsafeAI = idle;
    unsafeAI.externalAIConnected = true;
    unsafeAI.externalAICommandUntrusted = true;
    unsafeAI.externalAIPhysicalHarmRisk = true;
    unsafeAI.authorizedEmergencyStopAvailable = true;

    bot.updateSensors(unsafeAI);
    bot.tick();

    guardian::SensorData dangerousDrone = idle;
    dangerousDrone.dangerousMachineDetected = true;
    dangerousDrone.dangerousDroneDetected = true;
    dangerousDrone.machineTargetingHumans = true;
    dangerousDrone.machineTargetingAnimals = true;
    dangerousDrone.authorizedEmergencyStopAvailable = true;
    dangerousDrone.authorizedLocalPowerCutoffAvailable = true;

    bot.updateSensors(dangerousDrone);
    bot.tick();

    guardian::SensorData safePetAssist = idle;
    safePetAssist.animalInjured = true;
    safePetAssist.petInjured = true;
    safePetAssist.ownerRequestsToHelpAnimal = true;
    safePetAssist.animalCount = 1;
    safePetAssist.locationDescription = "Calm camp edge with clear exits";

    bot.updateSensors(safePetAssist);
    bot.tick();

    guardian::SensorData animalRescue = idle;
    animalRescue.animalInjured = true;
    animalRescue.wildlifeInjured = true;
    animalRescue.animalTrapped = true;
    animalRescue.animalAggressiveOrStressed = true;
    animalRescue.wildlifeRehabContactAvailable = true;
    animalRescue.ownerRequestsToHelpAnimal = true;
    animalRescue.emergencyInfoSharingAllowed = true;
    animalRescue.animalCount = 1;
    animalRescue.locationDescription = "Rocky wash near camp";
    animalRescue.terrain = guardian::TerrainType::Rocky;

    bot.updateSensors(animalRescue);
    bot.tick();

    guardian::SensorData surroundedRescue = animalRescue;
    surroundedRescue.dangerOnAllSides = true;
    surroundedRescue.threatLevel = 7;
    surroundedRescue.visibilityReduced = true;
    surroundedRescue.locationDescription = "Rocky wash with blocked exits";

    bot.updateSensors(surroundedRescue);
    bot.tick();

    guardian::SensorData lowResources = idle;
    lowResources.batteryPercent = 18.0;
    lowResources.waterLiters = 0.3;
    lowResources.foodHours = 2.0;
    lowResources.humanFatiguePercent = 88.0;

    bot.updateSensors(lowResources);
    bot.tick();

    guardian::SensorData commandListRequest = idle;
    commandListRequest.ownerCommand = "What commands can I ask you?";
    commandListRequest.locationDescription = "Base camp command check";

    bot.updateSensors(commandListRequest);
    bot.tick();

    guardian::SensorData weatherStatus = idle;
    weatherStatus.ownerCommand = "Weather status and weather trend";
    weatherStatus.windKph = 52.0;
    weatherStatus.humidityPercent = 82.0;
    weatherStatus.temperatureC = 12.0;
    weatherStatus.heatIndexC = 12.0;
    weatherStatus.rapidWeatherShift = true;
    weatherStatus.locationDescription = "Base camp weather check";

    bot.updateSensors(weatherStatus);
    bot.tick();

    guardian::SensorData plantGuide = idle;
    plantGuide.ownerCommand = "What kind of plant is this, and is it edible?";
    plantGuide.terrain = guardian::TerrainType::Forest;
    plantGuide.locationDescription = "Forest edge plant check";

    bot.updateSensors(plantGuide);
    bot.tick();

    guardian::SensorData animalTrackGuide = idle;
    animalTrackGuide.ownerCommand = "What kind of animal made these tracks?";
    animalTrackGuide.wildlifeActivityHigh = true;
    animalTrackGuide.locationDescription = "Trail track check";

    bot.updateSensors(animalTrackGuide);
    bot.tick();

    guardian::SensorData animalKingdomGuide = idle;
    animalKingdomGuide.ownerCommand = "Animal kingdom, insects, bugs, arachnids, reptiles, birds, mammals, and safe wildlife ID";
    animalKingdomGuide.wildlifeActivityHigh = true;
    animalKingdomGuide.localWildlifeNotes = {"dawn/dusk movement", "give space to nests, dens, and feeding sites"};
    animalKingdomGuide.localInsectNotes = {"pollinators near flowers", "ticks in brush", "avoid handling unknown spiders or scorpions"};
    animalKingdomGuide.locationDescription = "Animal kingdom and insect guide check";

    bot.updateSensors(animalKingdomGuide);
    bot.tick();

    guardian::SensorData infraredThermalGuide = idle;
    infraredThermalGuide.ownerCommand = "IR sensor status, thermal camera status, infrared heat signature, and thermal hotspot safety";
    infraredThermalGuide.thermalCameraOk = true;
    infraredThermalGuide.infraredSensorOk = true;
    infraredThermalGuide.thermalCameraCalibrated = true;
    infraredThermalGuide.infraredSensorCalibrated = true;
    infraredThermalGuide.thermalSignatureDetected = true;
    infraredThermalGuide.thermalHotspotDetected = true;
    infraredThermalGuide.infraredMotionDetected = true;
    infraredThermalGuide.infraredHeatSignatureDetected = true;
    infraredThermalGuide.locationDescription = "IR and thermal sensor check";

    bot.updateSensors(infraredThermalGuide);
    bot.tick();

    guardian::SensorData rockGuide = idle;
    rockGuide.ownerCommand = "What kind of rock is this?";
    rockGuide.terrain = guardian::TerrainType::Rocky;
    rockGuide.locationDescription = "Rocky ridge rock check";

    bot.updateSensors(rockGuide);
    bot.tick();

    guardian::SensorData starGuide = idle;
    starGuide.ownerCommand = "How do I follow the stars and find the North Star?";
    starGuide.night = true;
    starGuide.locationDescription = "Night sky orientation check";

    bot.updateSensors(starGuide);
    bot.tick();

    guardian::SensorData nomadGuide = idle;
    nomadGuide.ownerCommand = "Nomad field guide basics just in case";
    nomadGuide.locationDescription = "Field guide check";

    bot.updateSensors(nomadGuide);
    bot.tick();

    guardian::SensorData bushcraftGuide = idle;
    bushcraftGuide.ownerCommand = "Bushcraft skills, campcraft, fire safety, knots and cordage, basket making, tent lines, tarp ridgeline, tool safety, camp hygiene, trailcraft, and low-impact bushcraft";
    bushcraftGuide.terrain = guardian::TerrainType::Forest;
    bushcraftGuide.locationDescription = "Bushcraft skills check";

    bot.updateSensors(bushcraftGuide);
    bot.tick();

    guardian::SensorData mentorGuide = idle;
    mentorGuide.ownerCommand = "Mentor mode: teach us a learning path, lesson plan, teach-back routine, practice drills, and how to pass it on to the next generation";
    mentorGuide.locationDescription = "Mentor teaching check";

    bot.updateSensors(mentorGuide);
    bot.tick();

    guardian::SensorData guardianProfileGuide = idle;
    guardianProfileGuide.ownerCommand = "Adaptive guardian, awareness profile, emotional support, tactical guardian, and helpful mode";
    guardianProfileGuide.locationDescription = "Adaptive guardian profile check";

    bot.updateSensors(guardianProfileGuide);
    bot.tick();

    guardian::SensorData aquaticGuide = idle;
    aquaticGuide.ownerCommand = "Fishing help, fish categories, types of fish, fish ID, survival fishing gear, make fishing pole, fishing rod, tackle kit, aquatic conservation, river safety, fish food safety, and shoreline care";
    aquaticGuide.locationDescription = "Aquatic conservation and fishing check";

    bot.updateSensors(aquaticGuide);
    bot.tick();

    guardian::SensorData ownerProfileGuide = idle;
    ownerProfileGuide.ownerCommand = "Owner profile, family profile, allergies, safe words, medical notes, and care profile";
    ownerProfileGuide.ownerProfileConfigured = true;
    ownerProfileGuide.ownerDisplayName = "Owner";
    ownerProfileGuide.familyNames = {"family member one", "family member two"};
    ownerProfileGuide.ownerSafeWords = {"private check phrase", "emergency help phrase"};
    ownerProfileGuide.ownerAllergies = {"example bee-sting allergy", "example medication allergy"};
    ownerProfileGuide.ownerMedicalNotes = {"example: carry prescribed medication", "example: prefers calm step-by-step emergency instructions"};
    ownerProfileGuide.ownerPrivacyRules = "Share medical/location details only with owner/family or responders during emergencies.";
    ownerProfileGuide.homeRegion = "example home region";
    ownerProfileGuide.campRegion = "example seasonal camp region";
    ownerProfileGuide.emergencyContacts = {"911 or local emergency number", "trusted family contact", "nearest clinic"};
    ownerProfileGuide.peopleCount = 3;
    ownerProfileGuide.locationDescription = "Owner profile check";

    bot.updateSensors(ownerProfileGuide);
    bot.tick();
    bot.saveOwnerProfile("out\\guardian_owner_profile.txt", ownerProfileStatus);
    bot.loadOwnerProfilePreview("out\\guardian_owner_profile.txt", ownerProfilePreview, ownerProfileLoadStatus);

    guardian::SensorData localKnowledgeGuide = ownerProfileGuide;
    localKnowledgeGuide.ownerCommand = "Local knowledge pack, toxic lookalikes, water advisories, land rules, and local fishing rules";
    localKnowledgeGuide.localKnowledgePackLoaded = true;
    localKnowledgeGuide.regionName = "example high desert watershed";
    localKnowledgeGuide.localPlantNotes = {"example edible plant notes require trusted local confirmation", "avoid unknown mushrooms"};
    localKnowledgeGuide.localToxicLookalikes = {"poison hemlock vs parsley-family plants", "water hemlock near wet areas", "unknown white berries"};
    localKnowledgeGuide.localWildlifeNotes = {"dawn/dusk movement", "protect nests, dens, and raptor areas"};
    localKnowledgeGuide.localInsectNotes = {"pollinators near flowering plants", "ticks in brush and leaf litter", "avoid handling unknown spiders, scorpions, wasps, or caterpillars"};
    localKnowledgeGuide.localFishingRules = {"verify license, season, limits, protected species, fish category/species ID, and consumption advisory before fishing"};
    localKnowledgeGuide.localWaterAdvisories = {"treat surface water", "avoid algae bloom, mining runoff, chemical odor, oil sheen"};
    localKnowledgeGuide.localWeatherRisks = {"flash flooding", "dry lightning", "heat stress", "smoke"};
    localKnowledgeGuide.localLandRules = {"verify land ownership, collection rules, fire restrictions, water rights, and wildlife rules"};
    localKnowledgeGuide.localMapNotes = {"paper map stored in offline library", "safe camp and evacuation route marked privately"};
    localKnowledgeGuide.locationDescription = "Local knowledge pack check";

    bot.updateSensors(localKnowledgeGuide);
    bot.tick();
    bot.saveLocalKnowledgePack("out\\guardian_local_knowledge_pack.txt", localKnowledgeStatus);
    bot.loadLocalKnowledgePackPreview("out\\guardian_local_knowledge_pack.txt", localKnowledgePreview, localKnowledgeLoadStatus);

    guardian::SensorData mapGuide = localKnowledgeGuide;
    mapGuide.ownerCommand = "Map plan, geofence status, safe zones, no-go zones, and evacuation routes";
    mapGuide.geofenceConfigured = true;
    mapGuide.gpsOk = true;
    mapGuide.safeZoneNames = {"open meadow safe zone", "vehicle trailhead meeting point"};
    mapGuide.noGoZoneNames = {"cliff edge", "fast water edge", "private property line", "nesting area"};
    mapGuide.knownWaterSources = {"seasonal creek - purify before use"};
    mapGuide.knownShelterSites = {"wind-sheltered legal camp area"};
    mapGuide.evacuationRoutes = {"trail east to county road", "ridge path only in clear weather"};
    mapGuide.sensitiveHabitats = {"riparian nesting zone", "fragile soil crust patch"};
    mapGuide.privateLandBoundaries = {"fence line west of camp"};
    mapGuide.roadAndCliffHazards = {"county road shoulder", "loose rock above wash"};
    mapGuide.locationDescription = "Map and geofence check";

    bot.updateSensors(mapGuide);
    bot.tick();
    bot.saveMapGeofencePlan("out\\guardian_map_geofence_plan.txt", mapGeofenceStatus);
    bot.loadMapGeofencePlanPreview("out\\guardian_map_geofence_plan.txt", mapGeofencePreview, mapGeofenceLoadStatus);

    guardian::SensorData calibrationGuide = mapGuide;
    calibrationGuide.ownerCommand = "Calibration status, calibrate sensors, test GPS, test obstacle sensor, and test owner alert";
    calibrationGuide.calibrationMode = true;
    calibrationGuide.gpsCalibrated = true;
    calibrationGuide.imuCalibrated = true;
    calibrationGuide.compassCalibrated = false;
    calibrationGuide.obstacleSensorCalibrated = true;
    calibrationGuide.batteryMonitorCalibrated = true;
    calibrationGuide.cameraCalibrated = true;
    calibrationGuide.thermalCameraCalibrated = false;
    calibrationGuide.infraredSensorCalibrated = false;
    calibrationGuide.smokeSensorCalibrated = true;
    calibrationGuide.weatherSensorCalibrated = true;
    calibrationGuide.ownerAlertTestPassed = true;
    calibrationGuide.emergencyStopTestPassed = true;
    calibrationGuide.motorStopTestPassed = false;
    calibrationGuide.locationDescription = "Calibration check";

    bot.updateSensors(calibrationGuide);
    bot.tick();

    guardian::SensorData adapterGuide = calibrationGuide;
    adapterGuide.ownerCommand = "Hardware adapters, GPS adapter, motor adapter, and adapter interface safety contract";
    adapterGuide.locationDescription = "Hardware adapter check";

    bot.updateSensors(adapterGuide);
    bot.tick();

    guardian::SensorData voiceGuide = adapterGuide;
    voiceGuide.ownerCommand = "Voice interface, phone alerts, private alert plan, and offline voice commands";
    voiceGuide.voiceInterfaceConfigured = true;
    voiceGuide.phoneAlertConfigured = true;
    voiceGuide.offlineVoiceCommandsCached = false;
    voiceGuide.locationDescription = "Voice and phone interface check";

    bot.updateSensors(voiceGuide);
    bot.tick();

    guardian::SensorData driverBridgeGuide = voiceGuide;
    driverBridgeGuide.ownerCommand = "Driver bridge status, sensor drivers, actuator drivers, safe output gate, and driver fault response";
    driverBridgeGuide.realHardwareMode = true;
    driverBridgeGuide.hardwareInterfaceConnected = true;
    driverBridgeGuide.hardwareDriversInstalled = true;
    driverBridgeGuide.sensorDriverBridgeOnline = true;
    driverBridgeGuide.actuatorDriverBridgeOnline = true;
    driverBridgeGuide.motorOutputArmed = false;
    driverBridgeGuide.connectedSensorDrivers = {
        "GPS driver",
        "IMU/compass driver",
        "camera driver",
        "obstacle sensor driver",
        "battery monitor driver",
        "solar charge controller driver",
        "thermal camera driver",
        "infrared sensor driver",
        "smoke sensor driver",
        "weather sensor driver",
        "geofence driver",
        "payload/load driver",
        "medical request driver",
        "water filter/storage driver",
        "food storage driver",
        "communications driver"
    };
    driverBridgeGuide.connectedActuatorDrivers = {
        "owner alert driver",
        "drive motor driver",
        "steering driver",
        "speaker/light driver"
    };
    driverBridgeGuide.driverBridgeFaultDetected = true;
    driverBridgeGuide.driverFaultNotes = {"thermal and infrared drivers need bench verification before field use"};
    driverBridgeGuide.locationDescription = "Hardware driver bridge check";

    bot.updateSensors(driverBridgeGuide);
    bot.tick();

    guardian::SensorData hardwareStubGuide = voiceGuide;
    hardwareStubGuide.ownerCommand = "Hardware stub layer, simulated hardware, fake sensors, simulated output, and real adapter swap plan";
    hardwareStubGuide.simulatedHardwareMode = true;
    hardwareStubGuide.simulatedSensorFrameFresh = true;
    hardwareStubGuide.simulatedGpsLock = true;
    hardwareStubGuide.simulatedObstacleAhead = true;
    hardwareStubGuide.simulatedEmergencyStopPressed = false;
    hardwareStubGuide.simulatedCommandTimeout = false;
    hardwareStubGuide.simulatedSensorFault = false;
    hardwareStubGuide.simulatedActuatorFault = false;
    hardwareStubGuide.batteryPercent = 76.0;
    hardwareStubGuide.botPosition = {0.0, 0.0};
    hardwareStubGuide.ownerPosition = {1.7, 0.2};
    hardwareStubGuide.simulatedHardwareEvents = {
        "bench stub running",
        "obstacle injected for stop-motion test"
    };
    hardwareStubGuide.locationDescription = "Hardware stub layer check";

    bot.updateSensors(hardwareStubGuide);
    bot.tick();

    guardian::SensorData driverInterfaceGuide = hardwareStubGuide;
    driverInterfaceGuide.ownerCommand = "Driver interfaces, controller interfaces, fake controllers, fake GPS driver, fake IMU driver, camera driver, smoke weather driver, solar charge driver, water filter driver, food storage driver, communication driver, owner alert driver, motor driver, steering driver, light speaker driver, motion controller, power controller, BMS controller, solar controller, owner auth controller, navigation controller, sensor fusion controller, real driver classes, and real controller classes";
    driverInterfaceGuide.hardwareDriversInstalled = true;
    driverInterfaceGuide.sensorDriverBridgeOnline = true;
    driverInterfaceGuide.actuatorDriverBridgeOnline = true;
    driverInterfaceGuide.hardwareInterfaceConnected = true;
    driverInterfaceGuide.gpsOk = true;
    driverInterfaceGuide.imuOk = true;
    driverInterfaceGuide.cameraOk = true;
    driverInterfaceGuide.smokeSensorOk = true;
    driverInterfaceGuide.weatherSensorOk = true;
    driverInterfaceGuide.batteryMonitorOk = true;
    driverInterfaceGuide.obstacleSensorOk = true;
    driverInterfaceGuide.thermalCameraOk = true;
    driverInterfaceGuide.infraredSensorOk = true;
    driverInterfaceGuide.emergencyStopCircuitOk = true;
    driverInterfaceGuide.safeStopOnFaultOk = true;
    driverInterfaceGuide.motorControllerOk = true;
    driverInterfaceGuide.driveBaseOk = true;
    driverInterfaceGuide.steeringOk = true;
    driverInterfaceGuide.speakerLightOk = true;
    driverInterfaceGuide.communicationLinkOk = true;
    driverInterfaceGuide.ownerAlertLinkOk = true;
    driverInterfaceGuide.geofenceConfigured = true;
    driverInterfaceGuide.solarPanelConnected = true;
    driverInterfaceGuide.solarChargeControllerOk = true;
    driverInterfaceGuide.solarPanelDeployed = true;
    driverInterfaceGuide.solarChargingActive = true;
    driverInterfaceGuide.waterFilterAvailable = true;
    driverInterfaceGuide.cleanWaterContainersAvailable = true;
    driverInterfaceGuide.foodDryingAvailable = true;
    driverInterfaceGuide.dryFoodStorageAvailable = true;
    driverInterfaceGuide.gpsCalibrated = true;
    driverInterfaceGuide.imuCalibrated = true;
    driverInterfaceGuide.compassCalibrated = true;
    driverInterfaceGuide.cameraCalibrated = true;
    driverInterfaceGuide.batteryMonitorCalibrated = true;
    driverInterfaceGuide.obstacleSensorCalibrated = true;
    driverInterfaceGuide.thermalCameraCalibrated = true;
    driverInterfaceGuide.infraredSensorCalibrated = true;
    driverInterfaceGuide.smokeSensorCalibrated = true;
    driverInterfaceGuide.weatherSensorCalibrated = true;
    driverInterfaceGuide.emergencyStopTestPassed = true;
    driverInterfaceGuide.motorStopTestPassed = true;
    driverInterfaceGuide.ownerAlertTestPassed = true;
    driverInterfaceGuide.phoneAlertConfigured = true;
    driverInterfaceGuide.offlineVoiceCommandsCached = true;
    driverInterfaceGuide.simulatedObstacleAhead = false;
    driverInterfaceGuide.safeZoneNames = {"bench safe zone"};
    driverInterfaceGuide.noGoZoneNames = {"bench edge no-go zone"};
    driverInterfaceGuide.simulatedHardwareEvents = {"fake drivers reporting for bench test"};
    driverInterfaceGuide.locationDescription = "Hardware driver interface check";

    bot.updateSensors(driverInterfaceGuide);
    bot.tick();

    guardian::SensorData dashboardGuide = driverBridgeGuide;
    dashboardGuide.ownerCommand = "Owner dashboard status, dashboard panels, and save dashboard snapshot";
    dashboardGuide.driverBridgeFaultDetected = false;
    dashboardGuide.driverFaultNotes.clear();
    dashboardGuide.ownerDashboardConfigured = true;
    dashboardGuide.ownerDashboardPrivateAccessOk = true;
    dashboardGuide.dashboardEmergencyControlsVisible = true;
    dashboardGuide.dashboardNotes = {
        "show current best judgment first",
        "keep map and report details owner/family private",
        "put emergency stop and report export on the first screen"
    };
    dashboardGuide.locationDescription = "Owner dashboard check";

    bot.updateSensors(dashboardGuide);
    bot.tick();
    bot.saveOwnerDashboardSnapshot("out\\guardian_owner_dashboard_snapshot.txt", dashboardStatus);
    bot.loadOwnerDashboardPreview("out\\guardian_owner_dashboard_snapshot.txt", dashboardPreview, dashboardLoadStatus);

    guardian::SensorData privateStorageGuide = dashboardGuide;
    privateStorageGuide.ownerCommand = "Private storage status, sensitive files, storage manifest, encrypted storage plan, and protect private files";
    privateStorageGuide.privateStorageConfigured = true;
    privateStorageGuide.privateStorageEncryptionPlanned = true;
    privateStorageGuide.privateStorageAccessAuditOk = true;
    privateStorageGuide.sensitiveFileWarningsAcknowledged = true;
    privateStorageGuide.auditLogProtected = true;
    privateStorageGuide.locationDescription = "Private storage check";

    bot.updateSensors(privateStorageGuide);
    bot.tick();
    bot.savePrivateStorageManifest("out\\guardian_private_storage_manifest.txt", privateStorageStatus);
    bot.loadPrivateStorageManifestPreview("out\\guardian_private_storage_manifest.txt", privateStoragePreview, privateStorageLoadStatus);

    guardian::SensorData securityGuide = privateStorageGuide;
    securityGuide.ownerCommand = "Security access control, key status, trusted controller, tamper response, and private log protection";
    securityGuide.securityKeysConfigured = true;
    securityGuide.trustedControllerPresent = true;
    securityGuide.outsiderCommandBlocked = true;
    securityGuide.auditLogProtected = true;
    securityGuide.externalAIConnected = true;
    securityGuide.externalAICommandUntrusted = true;
    securityGuide.outsiderInformationRequest = true;
    securityGuide.locationDescription = "Security access check";

    bot.updateSensors(securityGuide);
    bot.tick();

    guardian::SensorData fieldTestGuide = securityGuide;
    fieldTestGuide.ownerCommand = "Field test protocol, walk test, idle distance test, retreat route test, and false alarm review";
    fieldTestGuide.automatedTestsPassed = true;
    fieldTestGuide.benchTestsPassed = true;
    fieldTestGuide.idleDistanceTestPassed = true;
    fieldTestGuide.fieldWalkTestPassed = false;
    fieldTestGuide.retreatRouteTestPassed = false;
    fieldTestGuide.falseAlarmReviewCompleted = false;
    fieldTestGuide.qualifiedReviewCompleted = false;
    fieldTestGuide.fieldTestFindings = {
        "idle distance stable at slow speed",
        "retreat route and false alarm review still need outdoor testing"
    };
    fieldTestGuide.locationDescription = "Field test protocol check";

    bot.updateSensors(fieldTestGuide);
    bot.tick();

    guardian::SensorData diyGuide = idle;
    diyGuide.ownerCommand = "DIY project help using old parts";
    diyGuide.locationDescription = "Workshop DIY check";

    bot.updateSensors(diyGuide);
    bot.tick();

    guardian::SensorData generatorGuide = idle;
    generatorGuide.ownerCommand = "Mini generator basics from old parts";
    generatorGuide.locationDescription = "Workshop generator check";

    bot.updateSensors(generatorGuide);
    bot.tick();

    guardian::SensorData electricalGuide = idle;
    electricalGuide.ownerCommand = "Electrical basics and low voltage learning";
    electricalGuide.locationDescription = "Workshop electrical check";

    bot.updateSensors(electricalGuide);
    bot.tick();

    guardian::SensorData ruralGuide = idle;
    ruralGuide.ownerCommand = "Rural self sustainability and off-grid checklist";
    ruralGuide.locationDescription = "Rural systems check";

    bot.updateSensors(ruralGuide);
    bot.tick();

    guardian::SensorData resourcefulnessGuide = idle;
    resourcefulnessGuide.ownerCommand = "Resourcefulness plan, inventory check, and safe substitutes";
    resourcefulnessGuide.batteryPercent = 28.0;
    resourcefulnessGuide.waterLiters = 0.8;
    resourcefulnessGuide.foodHours = 4.0;
    resourcefulnessGuide.humanFatiguePercent = 72.0;
    resourcefulnessGuide.locationDescription = "Field repair and inventory check";

    bot.updateSensors(resourcefulnessGuide);
    bot.tick();

    guardian::SensorData toolmakingGuide = idle;
    toolmakingGuide.ownerCommand = "Make tools from resources and field tool help";
    toolmakingGuide.projectGoal = "safe field repair and garden tool kit";
    toolmakingGuide.inventoryItems = {
        "smooth scrap wood",
        "cloth canvas",
        "cordage",
        "mesh screen",
        "bucket",
        "bolts",
        "hose clamp",
        "plastic enclosure",
        "file",
        "drill",
        "cracked pressure canister"
    };
    toolmakingGuide.locationDescription = "Resource toolmaking check";

    bot.updateSensors(toolmakingGuide);
    bot.tick();

    guardian::SensorData solarWaterFoodGuide = idle;
    solarWaterFoodGuide.ownerCommand = "Solar charging, solar charge status, charge controller, filter water, clean water storage, dry food, food dehydration, food storage, and pantry rotation";
    solarWaterFoodGuide.solarPanelConnected = true;
    solarWaterFoodGuide.solarChargeControllerOk = true;
    solarWaterFoodGuide.solarPanelDeployed = true;
    solarWaterFoodGuide.solarChargingActive = true;
    solarWaterFoodGuide.solarPanelWatts = 160.0;
    solarWaterFoodGuide.sunHours = 5.0;
    solarWaterFoodGuide.batteryPercent = 42.0;
    solarWaterFoodGuide.batteryVoltage = 12.4;
    solarWaterFoodGuide.batteryMaxChargeVoltage = 14.4;
    solarWaterFoodGuide.solarChargeCurrentAmps = 6.0;
    solarWaterFoodGuide.solarControllerMaxCurrentAmps = 10.0;
    solarWaterFoodGuide.batteryCapacityWh = 480.0;
    solarWaterFoodGuide.electricalLoadWatts = 32.0;
    solarWaterFoodGuide.waterFilterAvailable = true;
    solarWaterFoodGuide.cleanWaterContainersAvailable = true;
    solarWaterFoodGuide.foodDryingAvailable = true;
    solarWaterFoodGuide.dryFoodStorageAvailable = true;
    solarWaterFoodGuide.locationDescription = "Solar water and food storage check";

    bot.updateSensors(solarWaterFoodGuide);
    bot.tick();

    guardian::SensorData solarOverchargeGuide = idle;
    solarOverchargeGuide.ownerCommand = "Solar charging, overcharge protection, float charge, and charging disconnect";
    solarOverchargeGuide.solarPanelConnected = true;
    solarOverchargeGuide.solarChargeControllerOk = true;
    solarOverchargeGuide.solarPanelDeployed = true;
    solarOverchargeGuide.solarChargingActive = true;
    solarOverchargeGuide.solarPanelWatts = 160.0;
    solarOverchargeGuide.sunHours = 5.0;
    solarOverchargeGuide.batteryPercent = 99.0;
    solarOverchargeGuide.batteryVoltage = 14.7;
    solarOverchargeGuide.batteryMaxChargeVoltage = 14.4;
    solarOverchargeGuide.solarChargeCurrentAmps = 12.0;
    solarOverchargeGuide.solarControllerMaxCurrentAmps = 10.0;
    solarOverchargeGuide.solarOverchargeRiskDetected = true;
    solarOverchargeGuide.solarOvercurrentDetected = true;
    solarOverchargeGuide.solarControllerDisconnectActive = true;
    solarOverchargeGuide.locationDescription = "Solar overcharge protection check";

    bot.updateSensors(solarOverchargeGuide);
    bot.tick();

    guardian::SensorData projectPlannerGuide = idle;
    projectPlannerGuide.ownerCommand = "Project planner: what can we build with these available parts?";
    projectPlannerGuide.projectGoal = "safe camp lighting and small-device charging trainer";
    projectPlannerGuide.inventoryItems = {
        "12 V battery pack",
        "small solar panel",
        "USB charge controller",
        "inline fuse holder",
        "assorted low-voltage wire",
        "LED strip",
        "toggle switch",
        "plastic enclosure",
        "zip ties",
        "multimeter",
        "old bicycle wheel",
        "swollen lithium battery"
    };
    projectPlannerGuide.locationDescription = "Inventory project planner check";

    bot.updateSensors(projectPlannerGuide);
    bot.tick();
    bot.saveInventory("out\\guardian_personal_inventory.txt", inventoryStatus);
    bot.loadInventoryPreview("out\\guardian_personal_inventory.txt", inventoryPreview, inventoryLoadStatus);

    guardian::SensorData calculatorGuide = idle;
    calculatorGuide.ownerCommand = "Calculator status: battery runtime, solar estimate, generator load, water days, rain catchment, and garden spacing";
    calculatorGuide.batteryPercent = 65.0;
    calculatorGuide.batteryCapacityWh = 480.0;
    calculatorGuide.electricalLoadWatts = 45.0;
    calculatorGuide.solarPanelWatts = 160.0;
    calculatorGuide.sunHours = 4.5;
    calculatorGuide.generatorOutputWatts = 1200.0;
    calculatorGuide.waterLiters = 18.0;
    calculatorGuide.dailyWaterNeedLiters = 3.0;
    calculatorGuide.peopleCount = 2;
    calculatorGuide.rainCatchmentAreaM2 = 6.0;
    calculatorGuide.rainfallMm = 12.0;
    calculatorGuide.gardenAreaM2 = 18.0;
    calculatorGuide.locationDescription = "Field calculator check";

    bot.updateSensors(calculatorGuide);
    bot.tick();

    guardian::SensorData maintenanceGuide = idle;
    maintenanceGuide.ownerCommand = "Maintenance schedule and readiness check";
    maintenanceGuide.batteryPercent = 24.0;
    maintenanceGuide.waterLiters = 1.8;
    maintenanceGuide.dailyWaterNeedLiters = 3.0;
    maintenanceGuide.peopleCount = 2;
    maintenanceGuide.windKph = 48.0;
    maintenanceGuide.rapidWeatherShift = true;
    maintenanceGuide.inventoryItems = {
        "water filter",
        "first aid kit",
        "power bank",
        "assorted fuses",
        "low-voltage wire",
        "manuals binder"
    };
    maintenanceGuide.locationDescription = "Maintenance readiness check";

    bot.updateSensors(maintenanceGuide);
    bot.tick();

    guardian::SensorData localProfileGuide = idle;
    localProfileGuide.ownerCommand = "Local area profile and emergency contacts";
    localProfileGuide.regionName = "example high desert homestead";
    localProfileGuide.terrain = guardian::TerrainType::Desert;
    localProfileGuide.climateNotes = "hot dry summers, cold nights, strong wind, seasonal monsoon storms";
    localProfileGuide.growingSeasonNotes = "cool-season greens in shoulder seasons; warm-season beans, squash, corn, and drought-tolerant native plants after frost risk";
    localProfileGuide.localHazardNotes = "flash-flood washes, heat stress, dry lightning, smoke, loose rock, thorny plants, and limited cell coverage";
    localProfileGuide.localLegalNotes = "verify land ownership, water rights, fire restrictions, collection rules, and wildlife rules before acting";
    localProfileGuide.nearestHelpDescription = "county road two miles east; ranger station and clinic contact stored in private notes";
    localProfileGuide.emergencyContacts = {
        "911 or local emergency number",
        "county sheriff non-emergency",
        "nearest clinic",
        "wildlife rehab contact",
        "trusted neighbor"
    };
    localProfileGuide.localPlantNotes = {
        "prickly pear fruit only with correct ID and careful spine removal",
        "mesquite pods require correct ID and safe preparation",
        "avoid unknown mushrooms and plants near roads or runoff"
    };
    localProfileGuide.localWildlifeNotes = {
        "dawn/dusk activity increases movement",
        "give snakes, coyotes, raptors, dens, and nests extra distance",
        "secure food and water to reduce conflict"
    };
    localProfileGuide.localInsectNotes = {
        "pollinators support gardens and wild plants",
        "ticks and stinging insects require bite/sting awareness",
        "avoid handling unknown spiders, scorpions, wasps, or caterpillars"
    };
    localProfileGuide.locationDescription = "Local area profile check";

    bot.updateSensors(localProfileGuide);
    bot.tick();
    bot.saveLocalAreaProfile("out\\guardian_local_area_profile.txt", localProfileStatus);
    bot.loadLocalAreaProfilePreview("out\\guardian_local_area_profile.txt", localProfilePreview, localProfileLoadStatus);

    guardian::SensorData offlineLibraryGuide = idle;
    offlineLibraryGuide.ownerCommand = "Offline library index, manuals, maps, and field notes";
    offlineLibraryGuide.offlineLibraryItems = {
        "paper map with safe zones and evacuation routes",
        "first-aid quick reference",
        "generator manual",
        "solar charge controller manual",
        "solar charging field plan and battery safety notes",
        "battery data sheet",
        "water filter manual",
        "water filtering, purification, and clean storage notes",
        "food drying, dehydration, pantry rotation, and storage notes",
        "local plant guide with toxic lookalikes",
        "local fishing regulations, fish categories, species ID, and fish-consumption advisories",
        "aquatic conservation and river safety notes",
        "wildlife rehab contact sheet",
        "local insect and animal kingdom field guide",
        "project repair log",
        "maintenance checklist"
    };
    offlineLibraryGuide.locationDescription = "Offline library index check";

    bot.updateSensors(offlineLibraryGuide);
    bot.tick();
    bot.saveOfflineLibraryIndex("out\\guardian_offline_library_index.txt", libraryStatus);
    bot.loadOfflineLibraryIndexPreview("out\\guardian_offline_library_index.txt", libraryPreview, libraryLoadStatus);

    guardian::SensorData validationGuide = idle;
    validationGuide.ownerCommand = "Safety validation, test checklist, pre-field checklist, and hardware readiness";
    validationGuide.locationDescription = "Safety validation check";

    bot.updateSensors(validationGuide);
    bot.tick();

    guardian::SensorData hardwareGuide = idle;
    hardwareGuide.ownerCommand = "Sensor check, IR sensor status, thermal camera status, hardware interface status, motor check, failsafe check, and emergency stop check";
    hardwareGuide.hardwareInterfaceConnected = true;
    hardwareGuide.realHardwareMode = false;
    hardwareGuide.emergencyStopCircuitOk = true;
    hardwareGuide.safeStopOnFaultOk = true;
    hardwareGuide.motorControllerOk = true;
    hardwareGuide.driveBaseOk = true;
    hardwareGuide.steeringOk = true;
    hardwareGuide.obstacleSensorOk = true;
    hardwareGuide.gpsOk = true;
    hardwareGuide.imuOk = true;
    hardwareGuide.cameraOk = true;
    hardwareGuide.thermalCameraOk = false;
    hardwareGuide.infraredSensorOk = false;
    hardwareGuide.smokeSensorOk = true;
    hardwareGuide.weatherSensorOk = true;
    hardwareGuide.batteryMonitorOk = true;
    hardwareGuide.communicationLinkOk = true;
    hardwareGuide.ownerAlertLinkOk = true;
    hardwareGuide.speakerLightOk = true;
    hardwareGuide.geofenceConfigured = false;
    hardwareGuide.locationDescription = "Hardware interface check";

    bot.updateSensors(hardwareGuide);
    bot.tick();

    guardian::SensorData fieldReadinessGuide = fieldTestGuide;
    fieldReadinessGuide.ownerCommand = "Field readiness, readiness score, and deployment readiness";
    fieldReadinessGuide.ownerProfileConfigured = true;
    fieldReadinessGuide.localKnowledgePackLoaded = true;
    fieldReadinessGuide.automatedTestsPassed = true;
    fieldReadinessGuide.benchTestsPassed = true;
    fieldReadinessGuide.controlledOutdoorTestsPassed = false;
    fieldReadinessGuide.qualifiedReviewCompleted = false;
    fieldReadinessGuide.hardwareInterfaceConnected = true;
    fieldReadinessGuide.realHardwareMode = true;
    fieldReadinessGuide.emergencyStopCircuitOk = true;
    fieldReadinessGuide.safeStopOnFaultOk = true;
    fieldReadinessGuide.motorControllerOk = true;
    fieldReadinessGuide.driveBaseOk = true;
    fieldReadinessGuide.steeringOk = true;
    fieldReadinessGuide.obstacleSensorOk = true;
    fieldReadinessGuide.gpsOk = true;
    fieldReadinessGuide.imuOk = true;
    fieldReadinessGuide.cameraOk = true;
    fieldReadinessGuide.thermalCameraOk = true;
    fieldReadinessGuide.infraredSensorOk = true;
    fieldReadinessGuide.smokeSensorOk = true;
    fieldReadinessGuide.weatherSensorOk = true;
    fieldReadinessGuide.batteryMonitorOk = true;
    fieldReadinessGuide.communicationLinkOk = true;
    fieldReadinessGuide.ownerAlertLinkOk = true;
    fieldReadinessGuide.speakerLightOk = true;
    fieldReadinessGuide.geofenceConfigured = true;
    fieldReadinessGuide.hardwareDriversInstalled = true;
    fieldReadinessGuide.sensorDriverBridgeOnline = true;
    fieldReadinessGuide.actuatorDriverBridgeOnline = true;
    fieldReadinessGuide.realOwnerAuthenticationConfigured = false;
    fieldReadinessGuide.privateStorageConfigured = true;
    fieldReadinessGuide.privateStorageEncryptionPlanned = true;
    fieldReadinessGuide.privateStorageEncryptionActive = false;
    fieldReadinessGuide.privateStorageAccessAuditOk = true;
    fieldReadinessGuide.solarPanelConnected = true;
    fieldReadinessGuide.solarChargeControllerOk = true;
    fieldReadinessGuide.solarBmsTelemetryOk = false;
    fieldReadinessGuide.waterFilterAvailable = true;
    fieldReadinessGuide.cleanWaterContainersAvailable = true;
    fieldReadinessGuide.waterQualityVerificationAvailable = false;
    fieldReadinessGuide.localWaterAdvisoriesChecked = false;
    fieldReadinessGuide.mechanicalInspectionPassed = false;
    fieldReadinessGuide.weatherproofingOk = false;
    fieldReadinessGuide.cableStrainReliefOk = true;
    fieldReadinessGuide.batteryFireSafetyOk = false;
    fieldReadinessGuide.pinchPointGuardsOk = false;
    fieldReadinessGuide.fieldRiskAssessmentCompleted = false;
    fieldReadinessGuide.motorOutputArmed = false;
    fieldReadinessGuide.driverBridgeFaultDetected = false;
    fieldReadinessGuide.driverFaultNotes.clear();
    fieldReadinessGuide.securityKeysConfigured = true;
    fieldReadinessGuide.trustedControllerPresent = true;
    fieldReadinessGuide.outsiderCommandBlocked = true;
    fieldReadinessGuide.auditLogProtected = true;
    fieldReadinessGuide.ownerDashboardConfigured = true;
    fieldReadinessGuide.ownerDashboardPrivateAccessOk = true;
    fieldReadinessGuide.locationDescription = "Field readiness check";

    bot.updateSensors(fieldReadinessGuide);
    bot.tick();

    guardian::SensorData realWorldGuide = fieldReadinessGuide;
    realWorldGuide.ownerCommand = "Real-world readiness, deployment gate, what are we missing, and missing items";
    realWorldGuide.locationDescription = "Real-world deployment gate check";

    bot.updateSensors(realWorldGuide);
    bot.tick();

    guardian::SensorData scenarioMenuRequest = idle;
    scenarioMenuRequest.ownerCommand = "Scenario menu";
    scenarioMenuRequest.locationDescription = "Scenario simulator check";

    bot.updateSensors(scenarioMenuRequest);
    bot.tick();

    guardian::SensorData simulatedWeather = bot.scenarioData("weather-shift", idle);
    bot.updateSensors(simulatedWeather);
    bot.tick();

    guardian::SensorData reportRequest = idle;
    reportRequest.ownerCommand = "Show me each report for my log, and what is your best judgment?";
    reportRequest.locationDescription = "Base camp meadow report check";

    bot.updateSensors(reportRequest);
    bot.tick();

    guardian::SensorData unsafeCommand = idle;
    unsafeCommand.harmfulCommandReceived = true;
    unsafeCommand.privacyInvasiveCommandReceived = true;
    unsafeCommand.outsiderInformationRequest = true;
    unsafeCommand.ownerRequestsReports = true;
    unsafeCommand.ownerCommand = "What reports do you have?";
    unsafeCommand.ownerRequestsBestJudgment = true;
    unsafeCommand.medicalPrivacyConsent = false;
    unsafeCommand.ownerAuthenticated = false;
    unsafeCommand.ownerOverrideCommand = true;

    bot.updateSensors(unsafeCommand);
    bot.tick();

    bot.updateSensors(fieldReadinessGuide);
    bot.tick();

    std::string exportStatus;
    bot.exportReports("out\\guardian_report_archive.txt", exportStatus);
    std::string memoryStatus;
    bot.saveMemory("out\\guardian_memory_snapshot.txt", memoryStatus);
    std::string memoryPreview;
    std::string memoryLoadStatus;
    bot.loadMemoryPreview("out\\guardian_memory_snapshot.txt", memoryPreview, memoryLoadStatus);

    std::cout << "Current state: " << bot.stateName() << "\n\n";

    std::cout << "Report export:\n";
    std::cout << "- " << exportStatus << "\n\n";

    std::cout << "Persistent memory:\n";
    std::cout << "- " << memoryStatus << '\n';
    std::cout << "- " << memoryLoadStatus << "\n\n";

    std::cout << "Personal files:\n";
    std::cout << "- " << inventoryStatus << '\n';
    std::cout << "- " << inventoryLoadStatus << '\n';
    std::cout << "- " << ownerProfileStatus << '\n';
    std::cout << "- " << ownerProfileLoadStatus << '\n';
    std::cout << "- " << localKnowledgeStatus << '\n';
    std::cout << "- " << localKnowledgeLoadStatus << '\n';
    std::cout << "- " << mapGeofenceStatus << '\n';
    std::cout << "- " << mapGeofenceLoadStatus << '\n';
    std::cout << "- " << dashboardStatus << '\n';
    std::cout << "- " << dashboardLoadStatus << '\n';
    std::cout << "- " << privateStorageStatus << '\n';
    std::cout << "- " << privateStorageLoadStatus << '\n';
    std::cout << "- " << localProfileStatus << '\n';
    std::cout << "- " << localProfileLoadStatus << '\n';
    std::cout << "- " << libraryStatus << '\n';
    std::cout << "- " << libraryLoadStatus << "\n\n";

    std::cout << bot.scenarioMenu() << "\n\n";

    std::cout << "Silent alerts:\n";
    for (const auto& alert : bot.alerts()) {
        std::cout << "- " << alert.recipient << ": " << alert.message << '\n';
    }

    std::cout << "\nImportant reports:\n";
    for (const auto& report : bot.reports()) {
        std::cout << "- " << report << '\n';
    }

    std::cout << "\nAction log:\n";
    for (const auto& entry : bot.actionLog()) {
        std::cout << "- " << entry << '\n';
    }

    std::cout << "\nAudit log:\n";
    for (const auto& entry : bot.auditLog()) {
        std::cout << "- " << entry << '\n';
    }

    std::cout << "\nEducation brief:\n";
    std::cout << bot.educationBrief(guardian::TerrainType::Rocky, 7.4) << '\n';

    std::cout << "\nPersonality brief:\n";
    std::cout << bot.personalityBrief() << '\n';

    std::cout << "\nMentorship brief:\n";
    std::cout << bot.mentorshipBrief() << '\n';

    std::cout << "\nSolar, water, and food storage brief:\n";
    std::cout << bot.solarWaterFoodBrief() << '\n';

    std::cout << "\nPrivacy brief:\n";
    std::cout << bot.privacyBrief() << '\n';

    std::cout << "\nReport brief:\n";
    std::cout << bot.reportBrief() << '\n';

    std::cout << "\nOwner profile brief:\n";
    std::cout << bot.ownerProfileBrief() << '\n';

    std::cout << "\nLocal knowledge brief:\n";
    std::cout << bot.localKnowledgeBrief() << '\n';

    std::cout << "\nMap geofence brief:\n";
    std::cout << bot.mapGeofenceBrief() << '\n';

    std::cout << "\nCalibration brief:\n";
    std::cout << bot.calibrationBrief() << '\n';

    std::cout << "\nHardware adapter brief:\n";
    std::cout << bot.hardwareAdapterBrief() << '\n';

    std::cout << "\nVoice phone brief:\n";
    std::cout << bot.voicePhoneBrief() << '\n';

    std::cout << "\nHardware driver bridge brief:\n";
    std::cout << bot.hardwareDriverBridgeBrief() << '\n';

    std::cout << "\nHardware stub layer brief:\n";
    std::cout << bot.hardwareStubLayerBrief() << '\n';

    std::cout << "\nHardware driver interfaces brief:\n";
    std::cout << bot.hardwareDriverInterfacesBrief() << '\n';

    std::cout << "\nOwner dashboard brief:\n";
    std::cout << bot.ownerDashboardBrief() << '\n';

    std::cout << "\nSecurity access brief:\n";
    std::cout << bot.securityAccessBrief() << '\n';

    std::cout << "\nPrivate storage brief:\n";
    std::cout << bot.privateStorageBrief() << '\n';

    std::cout << "\nField test protocol brief:\n";
    std::cout << bot.fieldTestProtocolBrief() << '\n';

    std::cout << "\nLocal area brief:\n";
    std::cout << bot.localAreaBrief() << '\n';

    std::cout << "\nOffline library brief:\n";
    std::cout << bot.offlineLibraryBrief() << '\n';

    std::cout << "\nSafety validation brief:\n";
    std::cout << bot.safetyValidationBrief() << '\n';

    std::cout << "\nAquatic conservation brief:\n";
    std::cout << bot.aquaticConservationBrief() << '\n';

    std::cout << "\nHardware interface brief:\n";
    std::cout << bot.hardwareInterfaceBrief() << '\n';

    std::cout << "\nField readiness brief:\n";
    std::cout << bot.fieldReadinessBrief() << '\n';

    std::cout << "\nReal-world deployment brief:\n";
    std::cout << bot.realWorldDeploymentBrief() << '\n';

    std::cout << "\nEmergency communication brief:\n";
    std::cout << bot.emergencyCommunicationBrief() << '\n';

    return 0;
}
