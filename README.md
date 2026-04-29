# Conservation Guardian Medic Bot

This project is a C++ brain/demo for a peaceful conservation guardian, medic, field guide, and readiness simulator. It is not real robot hardware yet.

## Open In Visual Studio

1. Open Visual Studio.
2. Choose `File > Open > Folder`.
3. Open this folder: `C:\Users\New User\OneDrive\Documents\New project`.
4. Let CMake configure.
5. Run `conservation_guardian_demo` for the demo output.
6. Run `conservation_guardian_tests` to check behavior tests.

## Useful Commands

Ask the demo through `SensorData::ownerCommand` examples in `src/main.cpp`.

- `what commands can I ask you?`
- `what reports do you have?`
- `owner profile`
- `local knowledge pack`
- `map plan`
- `geofence status`
- `calibration status`
- `hardware adapters`
- `voice interface`
- `driver bridge status`
- `hardware stub layer`
- `driver interfaces`
- `controller interfaces`
- `fake controllers`
- `motion controller`
- `power controller`
- `BMS controller`
- `solar controller`
- `navigation controller`
- `fake IMU driver`
- `camera driver`
- `smoke weather driver`
- `solar charge driver`
- `water filter driver`
- `food storage driver`
- `communication driver`
- `owner alert driver`
- `steering driver`
- `IR sensor status`
- `thermal camera status`
- `owner dashboard`
- `private storage status`
- `storage manifest`
- `encrypted storage plan`
- `security access control`
- `field test protocol`
- `field readiness`
- `real-world readiness`
- `deployment gate`
- `what are we missing?`
- `adaptive guardian`
- `awareness profile`
- `emotional support`
- `tactical guardian`
- `helpful mode`
- `sensor check`
- `safety validation`
- `fishing help`
- `fish categories`
- `types of fish`
- `fish ID`
- `survival fishing gear`
- `make fishing pole`
- `fishing rod`
- `tackle kit`
- `solar charging`
- `solar charge status`
- `charge controller`
- `overcharge protection`
- `float charge`
- `charging disconnect`
- `filter water`
- `clean water storage`
- `dry food`
- `food dehydration`
- `food storage`
- `pantry rotation`
- `animal kingdom`
- `insect or bug ID`
- `nomad field guide`
- `medical status`
- `water purification`
- `bushcraft skills`
- `campcraft`
- `fire safety`
- `knots and cordage`
- `basket making`
- `tent lines`
- `tarp ridgeline`
- `camp hygiene`
- `trailcraft`
- `low-impact bushcraft`
- `project planner`
- `make tools from resources`
- `field tool help`
- `mentor mode`
- `learning path`
- `teach-back`
- `practice drills`
- `pass it on to the next generation`

## Generated Demo Files

The demo writes private owner/family files to `out\`:

- `guardian_owner_profile.txt`
- `guardian_local_knowledge_pack.txt`
- `guardian_map_geofence_plan.txt`
- `guardian_owner_dashboard_snapshot.txt`
- `guardian_private_storage_manifest.txt`
- `guardian_personal_inventory.txt`
- `guardian_local_area_profile.txt`
- `guardian_offline_library_index.txt`
- `guardian_report_archive.txt`
- `guardian_memory_snapshot.txt`

Keep these private because they may contain routes, medical notes, contacts, resources, and safety details.

## Private Storage

The private storage layer marks generated files as owner/family-only, blocks private writes unless owner/family presence and owner authentication are true, and creates a manifest explaining which files are sensitive. The current demo uses plain text files for learning and testing. Future hardware/software work should replace the plain text helpers with reviewed authenticated encryption and owner-held keys before real private use.

## Hardware Layers

- Hardware stub layer: fake sensor frames and fake output commands for safe bench testing.
- Driver interfaces: fake GPS, battery, obstacle, emergency stop, motor, and light/speaker drivers that can later be replaced one at a time with real hardware drivers.
- Driver bridge: safety gate between the bot brain and any real hardware output.

## Safety Boundary

The bot must stay peaceful, non-harmful, privacy-respecting, and conservation-focused. Real hardware movement should stay disabled until emergency stop, safe stop on fault, owner authentication, calibration, geofence, communications, and qualified review are complete.
