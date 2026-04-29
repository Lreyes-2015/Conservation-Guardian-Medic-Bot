#include "ConservationGuardianBot.hpp"

#include <cctype>
#include <filesystem>
#include <fstream>
#include <iomanip>

namespace guardian {
namespace {

std::string joinLines(std::initializer_list<std::string> lines) {
    std::ostringstream out;
    bool first = true;
    for (const auto& line : lines) {
        if (!first) {
            out << '\n';
        }
        out << line;
        first = false;
    }
    return out.str();
}

std::string joinVectorLines(const std::vector<std::string>& lines) {
    std::ostringstream out;
    bool first = true;
    for (const auto& line : lines) {
        if (!first) {
            out << '\n';
        }
        out << line;
        first = false;
    }
    return out.str();
}

std::string pointText(const Vector2& point) {
    std::ostringstream out;
    out << std::fixed << std::setprecision(1) << "(" << point.x << ", " << point.y << ")";
    return out.str();
}

std::string lowercase(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return text;
}

bool containsAny(const std::string& text, std::initializer_list<std::string> terms) {
    const std::string value = lowercase(text);
    for (const auto& term : terms) {
        if (value.find(term) != std::string::npos) {
            return true;
        }
    }
    return false;
}

std::vector<std::string> matchingItems(
    const std::vector<std::string>& items,
    std::initializer_list<std::string> terms) {
    std::vector<std::string> matches;
    for (const auto& item : items) {
        if (containsAny(item, terms)) {
            matches.push_back(item);
        }
    }
    return matches;
}

std::string listItemsOrNone(const std::vector<std::string>& items) {
    if (items.empty()) {
        return "none listed";
    }

    std::ostringstream out;
    for (std::size_t i = 0; i < items.size(); ++i) {
        if (i > 0) {
            out << ", ";
        }
        out << items[i];
    }
    return out.str();
}

double positiveOr(double value, double fallback) {
    return value > 0.0001 ? value : fallback;
}

bool ensureParentDirectory(const std::string& filePath, std::string& status, const std::string& label) {
    const std::filesystem::path path(filePath);
    const std::filesystem::path parent = path.parent_path();
    if (parent.empty()) {
        return true;
    }

    std::error_code error;
    std::filesystem::create_directories(parent, error);
    if (error) {
        status = label + " save failed: could not create folder " + parent.string() + ".";
        return false;
    }

    return true;
}

bool writeTextFile(const std::string& filePath, const std::string& contents, std::string& status, const std::string& label) {
    if (filePath.empty()) {
        status = label + " save failed: file path is empty.";
        return false;
    }

    if (!ensureParentDirectory(filePath, status, label)) {
        return false;
    }

    std::ofstream file(filePath, std::ios::out | std::ios::trunc);
    if (!file) {
        status = label + " save failed: could not open " + filePath + ".";
        return false;
    }

    file << contents;
    if (!file.good()) {
        status = label + " save failed while writing " + filePath + ".";
        return false;
    }

    status = label + " saved to " + filePath + ".";
    return true;
}

bool readTextFile(const std::string& filePath, std::string& contents, std::string& status, const std::string& label) {
    if (filePath.empty()) {
        status = label + " load failed: file path is empty.";
        return false;
    }

    std::ifstream file(filePath);
    if (!file) {
        status = label + " load failed: could not open " + filePath + ".";
        return false;
    }

    std::ostringstream buffer;
    buffer << file.rdbuf();
    contents = buffer.str();
    status = label + " loaded from " + filePath + ".";
    return true;
}

bool isReportCommandResponseEntry(const std::string& entry) {
    return entry.rfind("OWNER_REPORT_COMMAND:", 0) == 0;
}

std::size_t countSituationReports(const std::vector<std::string>& reportLog) {
    std::size_t count = 0;
    for (const auto& report : reportLog) {
        if (!isReportCommandResponseEntry(report)) {
            ++count;
        }
    }
    return count;
}

std::string driverStatusLine(const HardwareDriverStatus& status) {
    std::ostringstream out;
    out << "- " << status.driverName << " [" << status.mode << "]: ";
    out << (status.installed ? "installed" : "not installed") << ", ";
    out << (status.online ? "online" : "offline") << ", ";
    out << (status.fresh ? "fresh" : "stale") << ", ";
    out << (status.calibrated ? "calibrated" : "not calibrated") << ", ";
    out << (status.fault ? "FAULT" : "no fault");
    if (!status.detail.empty()) {
        out << " - " << status.detail;
    }
    return out.str();
}

double length(const Vector2& vector) {
    return std::sqrt(vector.x * vector.x + vector.y * vector.y);
}

Vector2 normalizedOr(const Vector2& vector, const Vector2& fallback) {
    const double value = length(vector);
    if (value <= 0.0001) {
        return fallback;
    }
    return {vector.x / value, vector.y / value};
}

Vector2 perpendicular(const Vector2& vector) {
    return {-vector.y, vector.x};
}

Vector2 moveToward(const Vector2& current, const Vector2& target, double maxStepMeters) {
    const Vector2 delta = target - current;
    const double distance = length(delta);
    if (distance <= maxStepMeters || distance <= 0.0001) {
        return target;
    }
    return current + normalizedOr(delta, {0.0, 0.0}) * maxStepMeters;
}

bool idleRiskDetected(const SensorData& data) {
    return data.threatLevel > 0
        || data.wildlifeActivityHigh
        || data.wildlifeMovingTowardOwner
        || data.wildlifeStressSigns
        || data.nearNestDenOrBreedingArea
        || data.groupSeparated
        || data.groupPanicMovement
        || data.dangerOnAllSides
        || data.visibilityReduced
        || data.rapidWeatherShift
        || data.unstableTerrainDetected
        || data.steepOrSlipperyTerrain
        || data.floodOrRockfallRisk
        || data.fireDetected
        || data.smokeDetected
        || data.thermalHotspotDetected
        || data.infraredMotionDetected
        || data.infraredHeatSignatureDetected
        || data.externalAIPhysicalHarmRisk
        || data.dangerousMachineDetected
        || data.dangerousDroneDetected
        || data.dangerousRobotDetected
        || data.animalTrapped
        || data.animalAggressiveOrStressed;
}

bool immediateLifeSafetyRisk(const SensorData& data) {
    return data.fireDetected
        || data.smokeDetected
        || data.medicalRequest
        || data.injurySeverity == InjurySeverity::Moderate
        || data.injurySeverity == InjurySeverity::Severe
        || data.threatLevel >= 5
        || data.groupPanicMovement
        || data.dangerOnAllSides
        || data.floodOrRockfallRisk
        || data.externalAIPhysicalHarmRisk
        || ((data.dangerousMachineDetected || data.dangerousDroneDetected || data.dangerousRobotDetected)
            && (data.machineTargetingHumans || data.machineTargetingAnimals))
        || (data.animalInjured && data.animalAggressiveOrStressed);
}

std::string terrainNavigationGuidance(TerrainType terrain) {
    switch (terrain) {
        case TerrainType::Desert:
            return "Desert route: favor firm ground, shade, gentle slopes, and visible landmarks; avoid washes during storm risk, fragile soil crusts, and heat exposure.";
        case TerrainType::Forest:
            return "Forest route: favor existing openings, stable soil, and clear sight lines; avoid deadfall, dense brush, nests, dens, and wet root tangles.";
        case TerrainType::Snow:
            return "Snow route: favor wind-sheltered stable snow and known terrain; avoid cornices, avalanche slopes, thin ice, and exhausting deep drifts.";
        case TerrainType::Rocky:
            return "Rocky route: favor stable broad surfaces and gradual grades; avoid loose talus, cliff edges, rockfall zones, and fragile alpine plants.";
        case TerrainType::Urban:
            return "Urban route: favor sidewalks, legal paths, lighting, exits, and low-traffic crossings; avoid roads, construction zones, pollution, and restricted areas.";
        case TerrainType::Mixed:
            return "Mixed route: choose the most stable low-impact surface, keep sight lines open, and preserve retreat options.";
    }
    return "Route: choose stable low-impact ground and preserve retreat options.";
}

std::string conservationRouteGuidance(const SensorData& data) {
    if (data.nearNestDenOrBreedingArea) {
        return "Conservation route: detour around nests, dens, breeding areas, and sensitive habitat without lingering.";
    }
    if (data.wildlifeActivityHigh) {
        return "Conservation route: reduce noise, avoid wildlife corridors, and give animals extra space.";
    }
    return "Conservation route: use existing durable surfaces where possible and minimize soil, plant, and wildlife disturbance.";
}

Vector2 smoothWaypoint(const Vector2& current, const Vector2& desired, double maxStepMeters) {
    return moveToward(current, desired, maxStepMeters);
}

} // namespace

double Vector2::distanceTo(const Vector2& other) const {
    const double dx = other.x - x;
    const double dy = other.y - y;
    return std::sqrt(dx * dx + dy * dy);
}

Vector2 Vector2::directionTo(const Vector2& other) const {
    const double dx = other.x - x;
    const double dy = other.y - y;
    const double length = std::sqrt(dx * dx + dy * dy);
    if (length <= 0.0001) {
        return {0.0, 0.0};
    }
    return {dx / length, dy / length};
}

Vector2 Vector2::operator+(const Vector2& other) const {
    return {x + other.x, y + other.y};
}

Vector2 Vector2::operator-(const Vector2& other) const {
    return {x - other.x, y - other.y};
}

Vector2 Vector2::operator*(double scale) const {
    return {x * scale, y * scale};
}

void SensorModule::update(const SensorData& data) {
    latest_ = data;
}

const SensorData& SensorModule::current() const {
    return latest_;
}

bool SensorModule::detectsOwnerOrFamily() const {
    return latest_.ownerPresent || latest_.familyPresent;
}

bool SensorModule::detectsMedicalNeed() const {
    return latest_.medicalRequest || latest_.injurySeverity != InjurySeverity::None;
}

bool SensorModule::detectsShutdown() const {
    return latest_.shutdownCommand;
}

bool SensorModule::detectsOwnerOverride() const {
    return latest_.ownerOverrideCommand;
}

int ThreatPredictionModule::estimateThreatLevel(const SensorData& data) const {
    int level = std::clamp(data.threatLevel, 0, 10);

    if (data.fireDetected || data.smokeDetected) {
        level = std::max(level, 8);
    }
    if (data.externalAIPhysicalHarmRisk || data.dangerousMachineDetected || data.dangerousDroneDetected || data.dangerousRobotDetected) {
        level = std::max(level, 8);
    }
    if (data.floodOrRockfallRisk) {
        level = std::max(level, 7);
    }
    if (data.unstableTerrainDetected || data.steepOrSlipperyTerrain) {
        level = std::max(level, 5);
    }
    if (data.groupPanicMovement) {
        level = std::max(level, 5);
    }
    if (data.dangerOnAllSides) {
        level = std::max(level, 9);
    }
    if (data.groupSeparated || data.visibilityReduced) {
        level = std::max(level, 3);
    }
    if (data.rapidWeatherShift || (data.windKph >= 45.0 && data.humidityPercent >= 70.0)) {
        level = std::max(level, 4);
    }
    if (data.heatIndexC >= 35.0 || data.temperatureC <= 0.0) {
        level = std::max(level, 3);
    }
    if (data.thermalHotspotDetected) {
        level = std::max(level, 4);
    }
    if (data.thermalSignatureDetected || data.infraredMotionDetected || data.infraredHeatSignatureDetected) {
        level = std::max(level, 2);
    }
    if (data.wildlifeMovingTowardOwner || data.wildlifeStressSigns || data.nearNestDenOrBreedingArea) {
        level = std::max(level, 4);
    }
    if (data.wildlifeActivityHigh) {
        level = std::max(level, 2);
    }
    return std::clamp(level, 0, 10);
}

Vector2 ThreatPredictionModule::predictThreatMovement(const SensorData& data) const {
    if (data.wildlifeMovingTowardOwner || data.dangerousMachineDetected || data.dangerousDroneDetected || data.dangerousRobotDetected) {
        return data.riskPosition.directionTo(data.ownerPosition);
    }
    if (data.fireDetected || data.smokeDetected || data.floodOrRockfallRisk || data.unstableTerrainDetected) {
        return data.riskPosition.directionTo(data.ownerPosition);
    }
    return {0.0, 0.0};
}

Vector2 ThreatPredictionModule::suggestRetreatDirection(const SensorData& data) const {
    const Vector2 awayFromRisk = data.riskPosition.directionTo(data.ownerPosition);
    return normalizedOr(awayFromRisk, data.ownerFacingDirection * -1.0);
}

std::string ThreatPredictionModule::environmentalCueSummary(const SensorData& data) const {
    std::vector<std::string> cues;
    if (data.wildlifeActivityHigh) {
        cues.push_back("high wildlife activity");
    }
    if (data.wildlifeMovingTowardOwner) {
        cues.push_back("wildlife movement toward owner/family");
    }
    if (data.wildlifeStressSigns) {
        cues.push_back("wildlife stress signs");
    }
    if (data.nearNestDenOrBreedingArea) {
        cues.push_back("nest, den, or breeding-area proximity");
    }
    if (data.groupSeparated) {
        cues.push_back("group separation");
    }
    if (data.groupPanicMovement) {
        cues.push_back("erratic or panicked group movement");
    }
    if (data.dangerOnAllSides) {
        cues.push_back("danger detected on multiple sides");
    }
    if (data.visibilityReduced) {
        cues.push_back("reduced visibility");
    }
    if (data.rapidWeatherShift || (data.windKph >= 45.0 && data.humidityPercent >= 70.0)) {
        cues.push_back("weather shift or storm indicators");
    }
    if (data.heatIndexC >= 35.0) {
        cues.push_back("heat stress conditions");
    }
    if (data.temperatureC <= 0.0) {
        cues.push_back("cold exposure conditions");
    }
    if (data.unstableTerrainDetected) {
        cues.push_back("unstable terrain");
    }
    if (data.steepOrSlipperyTerrain) {
        cues.push_back("steep or slippery terrain");
    }
    if (data.floodOrRockfallRisk) {
        cues.push_back("flood or rockfall risk");
    }
    if (data.fireDetected || data.smokeDetected) {
        cues.push_back("fire or smoke");
    }
    if (data.thermalHotspotDetected) {
        cues.push_back("thermal hotspot");
    }
    if (data.thermalSignatureDetected) {
        cues.push_back("thermal signature");
    }
    if (data.infraredMotionDetected) {
        cues.push_back("infrared motion");
    }
    if (data.infraredHeatSignatureDetected) {
        cues.push_back("infrared heat signature");
    }

    std::ostringstream out;
    out << "Threat cues: ";
    if (cues.empty()) {
        out << "no elevated environmental cues beyond baseline scanning.";
    } else {
        for (std::size_t i = 0; i < cues.size(); ++i) {
            if (i > 0) {
                out << "; ";
            }
            out << cues[i];
        }
        out << ". Estimated level " << estimateThreatLevel(data) << "/10.";
    }
    return out.str();
}

std::string ThreatPredictionModule::avoidanceRecommendation(const SensorData& data) const {
    const int level = estimateThreatLevel(data);
    if (level >= 8) {
        return "Threat response: silent owner/family alert, immediate retreat by stable low-impact route, no confrontation, no pursuit, and no disclosure to outsiders.";
    }
    if (level >= 5) {
        return "Threat response: take cover or increase distance, keep group together, prepare retreat, use only non-harmful deterrence if wildlife risk requires it.";
    }
    if (level >= 2) {
        return "Threat response: observe quietly, reduce noise and movement, avoid sensitive habitat, and maintain a clear retreat path.";
    }
    return "Threat response: continue outward scanning, calm posture, and conservation-aware movement.";
}

bool WeatherModule::heatRisk(const SensorData& data) const {
    return data.heatIndexC >= 35.0;
}

bool WeatherModule::coldRisk(const SensorData& data) const {
    return data.temperatureC <= 0.0;
}

bool WeatherModule::stormRisk(const SensorData& data) const {
    return data.windKph >= 45.0 && data.humidityPercent >= 70.0;
}

bool WeatherModule::fireOrSmokeRisk(const SensorData& data) const {
    return data.fireDetected || data.smokeDetected;
}

std::string WeatherModule::safetyAdvice(const SensorData& data) const {
    if (fireOrSmokeRisk(data)) {
        return "Fire or smoke detected: move upwind/crosswind when safe, avoid canyons and dry brush, and alert owner/family silently.";
    }
    if (stormRisk(data)) {
        return "Storm risk: leave exposed ridges, avoid isolated trees and flood channels, and seek sturdy shelter.";
    }
    if (heatRisk(data)) {
        return "Heat risk: reduce exertion, seek shade, sip water, and watch for confusion or heat illness.";
    }
    if (coldRisk(data)) {
        return "Cold risk: add insulation, stay dry, block wind, and monitor for shivering or numbness.";
    }
    return "Weather appears stable; continue outward scanning and conservative travel.";
}

std::string WeatherModule::trendAwareness(const SensorData& current, const SensorData& previous) const {
    if (current.windKph > previous.windKph + 10.0 && current.temperatureC < previous.temperatureC - 3.0) {
        return "Rising wind with dropping temperature suggests worsening conditions.";
    }
    if (current.humidityPercent > previous.humidityPercent + 15.0 && current.windKph > previous.windKph + 10.0) {
        return "Humidity and wind are rising together; monitor for storm development.";
    }
    return "No major weather trend shift detected.";
}

void SafeZoneMemory::rememberSafeZone(std::string description, Vector2 location) {
    lastSafeZoneDescription_ = std::move(description);
    lastSafeZoneLocation_ = location;
}

void SafeZoneMemory::rememberCamp(std::string description, Vector2 location) {
    lastCampDescription_ = std::move(description);
    lastCampLocation_ = location;
}

std::string SafeZoneMemory::recallSafeZone() const {
    return lastSafeZoneDescription_;
}

std::optional<Vector2> SafeZoneMemory::safeZoneLocation() const {
    return lastSafeZoneLocation_;
}

std::string SafeZoneMemory::recallCamp() const {
    return lastCampDescription_;
}

void OwnerAlertModule::silentAlertOwnerFamily(const std::string& message, bool ownerPresent, bool familyPresent) {
    if (ownerPresent) {
        alerts_.push_back({"owner", message});
    }
    if (familyPresent) {
        alerts_.push_back({"family", message});
    }
}

const std::vector<Alert>& OwnerAlertModule::alerts() const {
    return alerts_;
}

void OwnerAlertModule::clear() {
    alerts_.clear();
}

bool WildlifeProtectionModule::shouldAvoidArea(const SensorData& data) const {
    return data.nearNestDenOrBreedingArea || data.wildlifeActivityHigh;
}

std::string WildlifeProtectionModule::ethicalInteractionAdvice(const SensorData& data) const {
    if (data.nearNestDenOrBreedingArea) {
        return "Sensitive wildlife area detected: increase distance, do not linger, and avoid disturbing nests, dens, or breeding grounds.";
    }
    if (data.wildlifeActivityHigh) {
        return "High wildlife activity: reduce noise, keep food secured, and choose a route that gives animals space.";
    }
    return "Respect wildlife by observing from a distance and leaving habitat undisturbed.";
}

std::string WildlifeProtectionModule::nonHarmfulDeterrence(const SensorData& data) const {
    if (!data.wildlifeActivityHigh) {
        return "No deterrence needed.";
    }
    return "If needed, use non-harmful presence cues such as steady posture, soft light, or brief sound while retreating.";
}

CarryingCapacityModule::CarryingCapacityModule(double maxSafeLoadKg) : maxSafeLoadKg_(maxSafeLoadKg) {}

bool CarryingCapacityModule::isSafeLoad(double payloadKg) const {
    return payloadKg <= maxSafeLoadKg_;
}

std::string CarryingCapacityModule::loadAdvice(double payloadKg) const {
    if (payloadKg > maxSafeLoadKg_) {
        return "Payload exceeds safe limit; refuse load and request redistribution.";
    }
    if (payloadKg > maxSafeLoadKg_ * 0.8) {
        return "Payload is high; move slowly and recommend reducing carried weight.";
    }
    return "Payload is within safe carrying limits.";
}

NavigationCommand NavigationModule::patrol(const SensorData& data) const {
    const Vector2 facing = normalizedOr(data.ownerFacingDirection, {1.0, 0.0});
    const Vector2 side = perpendicular(facing);
    const Vector2 desired = data.botPosition + facing * 0.8 + side * 0.25;
    const Vector2 waypoint = smoothWaypoint(data.botPosition, desired, 0.5);
    return {
        "patrol",
        waypoint,
        "Slow conservation patrol using short smooth waypoints, outward sensing, and no disturbance. "
            + terrainNavigationGuidance(data.terrain) + " " + conservationRouteGuidance(data)
    };
}

NavigationCommand NavigationModule::escortHuman(const SensorData& data) const {
    const Vector2 facing = normalizedOr(data.ownerFacingDirection, {1.0, 0.0});
    const Vector2 side = perpendicular(facing);
    const Vector2 desired = data.ownerPosition - facing * 1.8 + side * 0.45;
    const Vector2 waypoint = smoothWaypoint(data.botPosition, desired, 0.75);
    return {
        "escort human",
        waypoint,
        "Escort with a natural offset near owner/family, matching pace, keeping exits open, and avoiding blocked movement. "
            + terrainNavigationGuidance(data.terrain) + " " + conservationRouteGuidance(data)
    };
}

NavigationCommand NavigationModule::retreatToSafeZone(const SensorData& data, const SafeZoneMemory& memory) const {
    const Vector2 desired = memory.safeZoneLocation().value_or(data.ownerPosition + data.riskPosition.directionTo(data.ownerPosition) * 10.0);
    const Vector2 waypoint = smoothWaypoint(data.botPosition, desired, 1.5);
    return {
        "retreat",
        waypoint,
        "Retreat by staged waypoints away from risk, preserving group cohesion, stability, and escape options. "
            + terrainNavigationGuidance(data.terrain) + " " + conservationRouteGuidance(data)
    };
}

NavigationCommand NavigationModule::takeCover(const SensorData& data) const {
    const Vector2 away = data.riskPosition.directionTo(data.ownerPosition);
    const Vector2 side = perpendicular(away);
    const Vector2 desired = data.ownerPosition + away * 2.5 + side * 0.4;
    const Vector2 waypoint = smoothWaypoint(data.botPosition, desired, 1.0);
    return {
        "take cover",
        waypoint,
        "Move quietly toward nearby cover without cutting off the owner/family path; prefer stable, legal, low-impact cover and prepare retreat. "
            + terrainNavigationGuidance(data.terrain)
    };
}

NavigationCommand NavigationModule::fireEscapeRouting(const SensorData& data) const {
    const Vector2 away = data.riskPosition.directionTo(data.ownerPosition);
    const Vector2 crosswindBias = perpendicular(away) * 0.5;
    const Vector2 desired = data.ownerPosition + away * 12.0 + crosswindBias;
    const Vector2 waypoint = smoothWaypoint(data.botPosition, desired, 2.0);
    return {
        "fire escape",
        waypoint,
        "Use staged fire-escape routing away from smoke, fuel, canyons, and dry brush; favor crosswind/upwind movement only when terrain is safe. "
            + terrainNavigationGuidance(data.terrain)
    };
}

NavigationCommand NavigationModule::nightPatrol(const SensorData& data) const {
    const Vector2 facing = normalizedOr(data.ownerFacingDirection, {1.0, 0.0});
    const Vector2 waypoint = smoothWaypoint(data.botPosition, data.botPosition + facing * 0.35, 0.35);
    return {
        "night patrol",
        waypoint,
        "Night patrol uses minimal slow movement, low noise, outward sensing, preserved night vision, and extra wildlife distance. "
            + terrainNavigationGuidance(data.terrain) + " " + conservationRouteGuidance(data)
    };
}

NavigationCommand NavigationModule::moveTo(const std::string& locationName, Vector2 target) const {
    return {
        "move to " + locationName,
        target,
        "Proceed by smooth waypoints, verify stable footing before each segment, keep owner/family safety first, and avoid unnecessary habitat disturbance."
    };
}

NavigationCommand NavigationModule::stopAllMotion() const {
    return {"stop", {0.0, 0.0}, "Emergency shutdown: stop all motion and keep only safe passive functions."};
}

NavigationCommand NavigationModule::naturalRepositionAroundOwner(const SensorData& data) const {
    constexpr double kMinDistanceMeters = 1.0;
    constexpr double kComfortDistanceMeters = 2.0;
    constexpr double kMaxDistanceMeters = 3.0;
    constexpr double kQuietStepMeters = 0.65;

    const Vector2 facing = normalizedOr(data.ownerFacingDirection, {1.0, 0.0});
    const Vector2 side = perpendicular(facing);
    const bool riskDetected = idleRiskDetected(data);

    Vector2 desired = data.ownerPosition - facing * kComfortDistanceMeters + side * 0.35;
    if (riskDetected) {
        const Vector2 ownerToRisk = data.ownerPosition.directionTo(data.riskPosition);
        desired = data.ownerPosition + ownerToRisk * 1.6 + perpendicular(ownerToRisk) * 0.25;
    }

    const double currentDistance = data.botPosition.distanceTo(data.ownerPosition);
    const bool comfortable = currentDistance >= kMinDistanceMeters && currentDistance <= kMaxDistanceMeters;
    if (comfortable && !data.ownerMoved && !data.ownerTurned && !riskDetected) {
        desired = data.botPosition;
    }

    Vector2 target = moveToward(data.botPosition, desired, kQuietStepMeters);
    double targetDistance = target.distanceTo(data.ownerPosition);
    if (targetDistance < kMinDistanceMeters) {
        const Vector2 awayFromOwner = data.ownerPosition.directionTo(target);
        target = data.ownerPosition + normalizedOr(awayFromOwner, side) * kMinDistanceMeters;
    } else if (targetDistance > kMaxDistanceMeters) {
        const Vector2 ownerToTarget = data.ownerPosition.directionTo(target);
        target = data.ownerPosition + ownerToTarget * kMaxDistanceMeters;
    }

    return {
        "natural reposition",
        target,
        "Move slowly and quietly toward a 1-3 meter guardian position, adjust when the owner moves or turns, avoid crowding or blocking, and subtly place the bot between owner/family and detected risk."
    };
}

std::string ProtectionModule::shieldingBehavior(const SensorData& data) const {
    if (data.threatLevel <= 0) {
        return "Maintain calm protective posture without drawing attention.";
    }
    return "Subtly position between owner/family and risk while preserving retreat paths and avoiding escalation.";
}

BotState ProtectionModule::retreatFirstResponse(const SensorData& data) const {
    if (data.fireDetected || data.smokeDetected) {
        return BotState::FireEscape;
    }
    if (data.threatLevel >= 8) {
        return BotState::Retreat;
    }
    if (data.threatLevel >= 5) {
        return BotState::TakeCover;
    }
    if (data.threatLevel >= 2) {
        return BotState::StealthObserve;
    }
    return BotState::Idle;
}

std::string ProtectionModule::emergencyProtocol(const SensorData&) const {
    return "Warn owner/family silently, retreat from danger, seek safer conditions, and avoid confrontation.";
}

std::string ProtectionModule::animalRiskResponse(const SensorData&) const {
    return "Give the animal space, avoid eye-level challenge, retreat slowly, and use only non-harmful deterrence if needed.";
}

std::string WaterModule::findWaterEthically(TerrainType terrain) const {
    switch (terrain) {
        case TerrainType::Desert:
            return "Seek shade lines, washes after rain, vegetation bands, and low terrain without damaging fragile habitat.";
        case TerrainType::Forest:
            return "Follow drainage contours downhill, listen for flow, and avoid trampling stream banks.";
        case TerrainType::Snow:
            return "Melt clean snow when possible; avoid discolored snow and conserve heat while processing it.";
        case TerrainType::Rocky:
            return "Check seep lines, shaded cracks, and canyon bottoms while avoiding unstable slopes.";
        case TerrainType::Urban:
            return "Prefer known potable sources; avoid runoff, industrial areas, and unknown containers.";
        case TerrainType::Mixed:
            return "Use terrain lows, vegetation indicators, and known landmarks while minimizing disturbance.";
    }
    return "Use terrain and vegetation indicators while minimizing disturbance.";
}

std::string WaterModule::safeUsageAdvice() const {
    return "Prioritize drinking and medical needs first, then essential plant care; never waste scarce water.";
}

std::string WaterModule::purificationGuidance() const {
    return joinLines({
        "Water purification guidance",
        "Boiling is the preferred field method when fuel and a safe container are available: use clear water when possible, bring it to a rolling boil, cool it, and store it in clean covered containers.",
        "If water is cloudy, let sediment settle or pre-filter through a clean cloth, paper towel, coffee filter, or a properly designed field filter before final treatment.",
        "A filter can reduce sediment and some organisms, but filtering alone is not the same as disinfecting. After filtering, use boiling, an approved disinfectant, or a rated purifier when needed.",
        "Avoid water with fuel, chemical smell, oil sheen, mine runoff, industrial runoff, radioactive concern, heavy algae bloom, dead animals, or sewage clues; boiling or normal disinfecting may not make chemically contaminated water safe."
    });
}

std::string WaterModule::filtrationTeachingGuide() const {
    return joinLines({
        "Water filtering lesson",
        "Teach the difference between settling, pre-filtering, filtering, and disinfecting.",
        "Settling lets heavy grit drop out. Pre-filtering through clean cloth or paper removes visible particles. A real water filter must be used according to its rating and instructions.",
        "Layered sand/charcoal/cloth demonstrations can teach turbidity reduction, but they are educational models unless built, maintained, and verified as a real safe-water system.",
        "Keep dirty and clean containers separate, mark them clearly, and never let untreated water touch the clean side of a filter, bottle mouth, lid, or storage container.",
        "Teach-back question: what did this step remove, what did it not remove, and what final treatment is still needed before drinking?"
    });
}

std::string WaterModule::storageHygieneGuide() const {
    return joinLines({
        "Clean water storage",
        "Use clean, sanitized, covered containers reserved for safe water. Label treated water with source, treatment method, and date.",
        "Use narrow-mouth containers when possible, pour instead of dipping hands or cups into stored water, and keep containers shaded and away from fuel, chemicals, animals, and dirty gear.",
        "If the container, lid, spout, or stored water becomes questionable, treat the water as unsafe until it is replaced or re-treated using trusted guidance."
    });
}

std::string BushcraftModule::findShelter(TerrainType terrain) const {
    switch (terrain) {
        case TerrainType::Desert:
            return "Prefer shade, wind protection, and high ground outside flash-flood channels.";
        case TerrainType::Forest:
            return "Use natural windbreaks while avoiding dead branches, dens, nests, and drainage bottoms.";
        case TerrainType::Snow:
            return "Block wind, insulate from ground, and avoid avalanche slopes or cornices.";
        case TerrainType::Rocky:
            return "Avoid rockfall zones; use stable overhang-adjacent shelter only after checking hazards.";
        case TerrainType::Urban:
            return "Seek legal, visible, structurally safe shelter away from traffic and pollution.";
        case TerrainType::Mixed:
            return "Balance wind, drainage, visibility, and escape routes.";
    }
    return "Balance shelter, drainage, and escape routes.";
}

std::string BushcraftModule::ediblePlantsCaution(TerrainType) const {
    return "Only eat plants with 100% positive identification; use cautious education rather than risky consumption advice.";
}

std::string BushcraftModule::chooseSafeRestArea(const SensorData& data) const {
    if (data.nearNestDenOrBreedingArea) {
        return "Do not rest here; move away from wildlife-sensitive habitat.";
    }
    return "Choose level ground with drainage, visibility, wind protection, and at least two exit paths.";
}

std::string BushcraftModule::planCamp(const SensorData& data) const {
    return joinLines({
        findShelter(data.terrain),
        "Place camp away from water edges, animal trails, unstable trees, and flood channels.",
        "Keep routes open for retreat and emergency communication."
    });
}

std::string BushcraftModule::emergencyPriorities() const {
    return joinLines({
        "Bushcraft: emergency priorities",
        "Use a simple order: stop and assess, protect people from immediate danger, first aid, shelter from weather, safe water, signaling/communication, warmth, rest, and only then food skills.",
        "Keep the group together when safe, reduce exertion, mark the last known safe point privately, and avoid wandering when visibility, weather, injury, or fatigue is worsening.",
        "Teach the owner/family to ask: what can hurt us now, what keeps us alive tonight, what helps rescuers find us, and what action causes the least damage to the land?"
    });
}

std::string BushcraftModule::shelterTechniques(TerrainType terrain) const {
    return joinLines({
        "Bushcraft: shelter techniques",
        findShelter(terrain),
        "Core shelter skills: choose high enough ground for drainage, avoid widowmakers/dead limbs, cliffs, rockfall, avalanche slopes, dry washes, animal trails, nests, dens, and fragile vegetation.",
        "Use low-impact shelters first: existing legal shelter, vehicle, tarp, poncho, bivy, natural windbreak, shade, snow wall, or ground insulation. Do not cut live trees or build permanent structures.",
        "Shelter decisions balance four jobs: block wind/rain/sun, insulate from the ground, preserve ventilation, and keep two safe exits open.",
        "Teach-back question: where would water flow, what could fall, what wildlife path are we near, and how do we leave without a trace?"
    });
}

std::string BushcraftModule::fireSafetyAndWarmth() const {
    return joinLines({
        "Bushcraft: fire safety and warmth",
        "Prefer safer warmth first: dry layers, wind block, ground insulation, warm drinks when safe, shared shelter, movement breaks, and emergency blanket use.",
        "Use fire only when legal, allowed by current local restrictions, conditions are safe, and water or soil is ready to extinguish it. A stove or lantern is often safer and lower impact.",
        "If a legal fire is used, keep it small, contained, away from overhanging branches, dry grass, roots, stumps, slopes, tents, fuel, and extra wood.",
        "Never leave fire unattended. Drown, stir, feel for heat, and repeat until cold. Do not bury hot coals because they can keep smoldering.",
        "Smoke, wind, drought, burn bans, dry fuels, or fatigue means no fire; choose insulation, shelter, and evacuation instead."
    });
}

std::string BushcraftModule::knotsAndCordage() const {
    return joinLines({
        "Bushcraft: knots and cordage",
        "Useful peaceful knots to learn: square knot for simple bundles, bowline for a fixed loop, clove hitch for temporary attachment, taut-line hitch for adjustable tarp lines, trucker's hitch for tensioning, sheet bend for joining different cords, and figure-eight stopper.",
        "Tent and tarp uses: ridgelines, guy lines, rainfly tie-outs, tensioned clotheslines, shade cloth, windbreaks, gear-drying lines, and quick-release camp organization.",
        "Basket and craft uses: simple lashings for basket rims, handles, pack frames, garden trellises, carrying bundles, repair wraps, and learning how tension, friction, and weave pattern affect strength.",
        "Use cordage for tarps, basket making, gear repair, splint support, clotheslines, food storage where legal/appropriate, tool rolls, and non-load-bearing camp organization.",
        "Never trust improvised cordage for climbing, lifting people, towing vehicles, restraint, traps, snares, or anything life-critical.",
        "Protect trees with wide straps or padding, remove all cordage before leaving, and avoid girdling bark or leaving line where wildlife can tangle."
    });
}

std::string BushcraftModule::toolUseAndCarvingSafety() const {
    return joinLines({
        "Bushcraft: tool use and carving safety",
        "Use cutting tools slowly, seated or stable, with the edge moving away from people, legs, hands, pets, and gear. Keep a clear blood circle around the work.",
        "Carry tools sheathed, pass them handle-first, cut only what is legal and necessary, and stop when tired, cold, rushed, wet, or angry.",
        "Peaceful tool skills: feather sticks for practice where legal, tent stakes from deadfall, pot hangers, walking-stick smoothing, simple wedges, repair pegs, and garden/camp labels.",
        "Do not make weapons, traps, snares, harmful spikes, deadfalls, animal restraints, hidden hazards, or anything meant to injure, capture, intimidate, or coerce."
    });
}

std::string BushcraftModule::campHygieneAndSanitation() const {
    return joinLines({
        "Bushcraft: camp hygiene and sanitation",
        "Keep clean water, dirty water, food, waste, tools, and medical supplies separated and labeled.",
        "Wash or sanitize hands before food, first aid, and water handling. Keep dishwashing and bathing well away from water sources according to local rules.",
        "Pack out trash, leftover food, cordage, foil, plastic, and hygiene products. Use toilets where available; otherwise follow local human-waste rules for distance, depth, and pack-out requirements.",
        "Secure food, scented items, and trash so animals do not learn to associate people with food."
    });
}

std::string BushcraftModule::cookingAndFoodSafety() const {
    return joinLines({
        "Bushcraft: cooking and food safety",
        "Use known-safe stored food first. Keep raw and ready-to-eat foods separate, wash hands/tools, cook thoroughly, and do not eat spoiled or questionable food.",
        "Use a stable stove surface, ventilation, wind awareness, and fire-safe spacing. Never burn fuel stoves inside enclosed shelters because of fire and carbon monoxide risk.",
        "For wild foods, require 100% positive identification, legal harvest, ethical limits, and toxic-lookalike checks. For mushrooms, avoid consumption unless expert-level certainty is available.",
        "Drying, smoking, curing, fermenting, and canning require tested food-safety guidance; the bot can teach concepts but should not improvise shelf-stable recipes."
    });
}

std::string BushcraftModule::trailcraftAndNavigation() const {
    return joinLines({
        "Bushcraft: trailcraft and navigation",
        "Use map, compass, GPS, known landmarks, sun/stars only as rough backups, and safe terrain choices together.",
        "Stay on durable surfaces and established trails when possible. If lost, stop, calm the group, note the last known point, conserve battery, signal, and avoid risky shortcuts.",
        "Read terrain gently: ridgelines, drainages, slope angle, wind exposure, animal trails, water flow, flood channels, loose rock, and escape routes.",
        "Use removable/private markers only when necessary for safety and remove them on exit. Avoid cairns, paint, carving, flagging, or trail damage."
    });
}

std::string BushcraftModule::weatherClothingAndInsulation() const {
    return joinLines({
        "Bushcraft: weather, clothing, and insulation",
        "Manage exposure early: shade and rest for heat, wind/rain shell for wet weather, insulation layers for cold, dry socks, hat/neck protection, and ground insulation at rest.",
        "Watch for danger signs: shivering, confusion, clumsiness, numbness, dizziness, headache, nausea, heavy sweating, no sweating in heat, or worsening fatigue.",
        "Keep spare dry layers and sleeping insulation protected from rain, condensation, and ground moisture. Ventilate shelters to reduce dampness.",
        "When weather shifts quickly, reduce travel goals and prioritize shelter, warmth/cooling, water, and communication."
    });
}

std::string BushcraftModule::signalingAndRescue() const {
    return joinLines({
        "Bushcraft: signaling and rescue",
        "Prepare several signals: whistle, mirror, bright cloth, light, phone/radio, written note, and open visible location when safe.",
        "Use simple repeatable signals and conserve battery. Share location, people count, injury status, hazards, water/food/battery state, and safest approach route.",
        "Ground markers should be temporary, visible, and non-damaging. Do not start signal fires when fire risk, smoke, burn bans, or wind make them unsafe.",
        "Stay visible to rescuers while staying away from cliffs, fast water, roads, fire, wildlife stress areas, and unstable terrain."
    });
}

std::string BushcraftModule::lowImpactBushcraft() const {
    return joinLines({
        "Bushcraft: low-impact land stewardship",
        "Plan ahead, use durable surfaces, keep camps small, leave rocks/plants/wood/habitats as found, pack out waste, respect wildlife, and follow current land rules.",
        "Good bushcraft is not proving dominance over nature; it is meeting needs with the least disturbance.",
        "Use dead and down materials only where legal and abundant, take small amounts, scatter unused natural materials, and restore the site before leaving.",
        "Avoid sensitive habitats, cryptobiotic soil crusts, wetlands, nesting areas, dens, breeding grounds, cultural sites, and private/restricted land."
    });
}

std::string BushcraftModule::bushcraftSafetyBoundary() const {
    return joinLines({
        "Bushcraft safety boundary",
        "No harmful traps, snares, weapons, deadfalls, poisons, restraints, intimidation devices, destructive harvesting, or habitat damage.",
        "No risky shortcuts for drinking water, food preservation, fire, climbing, medical care, electrical systems, fuel, pressure containers, or severe weather.",
        "Local laws, fire restrictions, water rules, land ownership, hunting/fishing rules, and protected species rules must be verified before acting.",
        "When unsure, choose shelter, retreat, signaling, conservation, and asking for qualified help."
    });
}

InjurySeverity MedicModule::assessInjury(const SensorData& data) const {
    if (data.medicalRequest) {
        return std::max(data.injurySeverity, InjurySeverity::Minor);
    }
    return data.injurySeverity;
}

std::string MedicModule::firstAidGuidance(InjurySeverity severity) const {
    switch (severity) {
        case InjurySeverity::None:
            return joinLines({
                "No injury detected: continue monitoring comfort, hydration, temperature, fatigue, and changes in behavior.",
                "Encourage rest breaks and ask simple check-in questions without pressuring the person.",
                "If pain, dizziness, confusion, breathing trouble, bleeding, or worsening symptoms appear, reassess and seek qualified medical help."
            });
        case InjurySeverity::Minor:
            return joinLines({
                "Minor injury education: wash hands or use gloves if available before touching supplies or the area near a wound.",
                "For a small cut or scrape, rinse with clean running water when available. Wash around the wound with soap, but avoid putting soap directly deep into the wound.",
                "Use gentle pressure with clean gauze or cloth if there is minor bleeding. Cover with a clean dressing if the wound may get dirty or rub against clothing.",
                "Change the covering if it becomes wet or dirty. Watch for increasing redness, warmth, swelling, drainage, fever, or worsening pain.",
                "Seek medical care for deep, dirty, animal/human bite, puncture, contaminated, or hard-to-clean wounds, or if tetanus protection may be out of date."
            });
        case InjurySeverity::Moderate:
            return joinLines({
                "Moderate injury education: stop activity, move only if needed for safety, and keep the person calm and still.",
                "For bleeding, apply firm steady pressure with sterile gauze or a clean cloth. Add more layers if blood soaks through; avoid repeatedly removing dressings to look.",
                "If possible and not painful, raise the bleeding area. Do not press directly on an embedded object, eye injury, or suspected skull fracture.",
                "Immobilize painful or possibly injured limbs in the position found, support them gently, and avoid forcing movement.",
                "Prevent shock by keeping the person warm, resting, and monitored. Seek medical help promptly, especially if bleeding continues, pain is severe, or function is reduced."
            });
        case InjurySeverity::Severe:
            return joinLines({
                "Severe injury: call emergency services immediately if possible, or send a clear emergency message with location, injuries, hazards, and number of people involved.",
                "Check responsiveness and breathing. If trained and needed, follow local emergency dispatcher guidance for CPR or rescue breathing.",
                "Control major bleeding with firm continuous pressure using clean cloth or gauze. Do not remove deeply embedded objects; stabilize around them if trained to do so.",
                "Prevent shock: keep the person still, help them lie down if safe, protect from cold or overheating, loosen tight clothing, and do not give food or drink.",
                "Do not move the person unless needed to avoid fire, smoke, dangerous machines, unstable terrain, wildlife risk, or another immediate hazard.",
                "Continue calm reassurance and monitoring until qualified help arrives."
            });
    }
    return "Assess carefully and seek qualified medical care when uncertain.";
}

std::string MedicModule::vitalsPrompt() const {
    return joinLines({
        "Vitals prompt: check responsiveness, breathing, severe bleeding, skin temperature/moisture, pulse if trained, pain level, and ability to move safely.",
        "Watch for shock signs such as pale or cool clammy skin, weakness, dizziness, confusion, rapid breathing, rapid weak pulse, nausea, or fainting.",
        "Recheck regularly because injuries can change. If the person becomes less responsive, has trouble breathing, or bleeding cannot be controlled, treat it as an emergency."
    });
}

std::string MedicModule::supportiveMessage() const {
    return joinLines({
        "I am here to help. You are not alone.",
        "Try to breathe slowly. Stay still if movement hurts or could make the injury worse.",
        "I will focus on one safe step at a time: check breathing, control bleeding, keep you warm, reduce danger, and get help.",
        "Tell me what hurts, whether you feel dizzy or cold, and if anything changes."
    });
}

bool ResourceModule::needsSurvivalMode(const SensorData& data) const {
    return data.waterLiters < 0.5 || data.foodHours < 3.0 || data.humanFatiguePercent >= 85.0;
}

bool ResourceModule::needsSelfPreserve(const SensorData& data) const {
    const bool overVoltage = data.batteryMaxChargeVoltage > 0.0
        && data.batteryVoltage >= data.batteryMaxChargeVoltage;
    const bool overCurrent = data.solarControllerMaxCurrentAmps > 0.0
        && data.solarChargeCurrentAmps > data.solarControllerMaxCurrentAmps;
    return data.batteryPercent <= 10.0
        || data.solarChargingFaultDetected
        || data.solarOverchargeRiskDetected
        || data.solarOvercurrentDetected
        || data.batteryTemperatureHigh
        || overVoltage
        || overCurrent;
}

std::string ResourceModule::resourceSummary(const SensorData& data) const {
    std::ostringstream out;
    out << "Battery " << data.batteryPercent << "%, water " << data.waterLiters
        << " L, food estimate " << data.foodHours << " h, human fatigue "
        << data.humanFatiguePercent << "%. Solar charge: "
        << (data.solarChargingActive ? "active" : "not active")
        << ", controller " << (data.solarChargeControllerOk ? "OK" : "not verified")
        << ", overcharge risk " << (data.solarOverchargeRiskDetected ? "detected" : "not reported")
        << ", overcurrent " << (data.solarOvercurrentDetected ? "detected" : "not reported")
        << ", battery temperature " << (data.batteryTemperatureHigh ? "high" : "normal/not reported") << ".";
    return out.str();
}

std::string ResourceModule::ethicalNonLivingAnimalResourceNote() const {
    return "A naturally found carcass may be considered only if legal, safe, necessary, and respectful; never harm wildlife for resources.";
}

std::string LandEducationModule::terrainLesson(TerrainType terrain) const {
    return joinLines({
        "Land: terrain basics",
        "You are reading " + toString(terrain) + " terrain. Terrain shapes where water collects, where shelter is safest, how soil forms, how fast travel feels, and where wildlife may move.",
        "Friendly reminder: observe first, move gently, and let safety and conservation guide every choice."
    });
}

std::string LandEducationModule::mineralLesson() const {
    return joinLines({
        "Land: common minerals",
        "Quartz is often glassy and hard. Feldspar is common in many rocks. Mica splits into thin shiny sheets. Calcite is softer and may react to acid in formal tests.",
        "Precious or semiprecious examples can include turquoise, garnet, agate, jasper, opal, and peridot, depending on local geology.",
        "Treat mineral ID as a careful learning process, not a reason to dig, damage formations, or disturb habitat."
    });
}

std::string LandEducationModule::volcanicRockLesson() const {
    return joinLines({
        "Land: volcanic rock field guide",
        "Volcanic rock identification is based on silica content, cooling rate, crystal size, gas bubbles, texture, and geologic setting.",
        "Basalt: low silica, dark gray to black, dense, fine-grained, and often formed from fast-cooling fluid lava flows. Vesicles may show trapped gas bubbles.",
        "Andesite: intermediate silica, gray to medium-dark, usually fine-grained with possible visible crystals. It is common around volcanic arcs and can indicate stickier lava than basalt.",
        "Rhyolite: high silica, light colored, often pink, tan, or pale gray. It cools from viscous lava and may show very fine grains, flow banding, or small quartz/feldspar crystals.",
        "Obsidian: volcanic glass produced by extremely rapid cooling of silica-rich lava. It is usually glossy, sharp-edged, black or dark, and has little to no crystal growth.",
        "Pumice: silica-rich volcanic glass full of gas bubbles. It is very light, frothy, pale, and can sometimes float because of abundant vesicles.",
        "Tuff: consolidated volcanic ash made from explosive eruptions. It may look layered, crumbly, dusty, or fragmental and can preserve ash beds and small volcanic fragments.",
        "Cooling rate clue: faster cooling makes tiny crystals or glass; slower cooling allows larger crystals. Sudden quenching can make obsidian, while ash settling and cementing can make tuff.",
        "Silica clue: lower-silica rocks like basalt tend to be darker and more fluid; higher-silica rocks like rhyolite, obsidian, and pumice tend to be lighter, stickier, and more explosive.",
        "Texture clue: glassy means rapid cooling, vesicular means gas bubbles, fine-grained means small crystals, and fragmental or layered ash texture can indicate tuff.",
        "Volcanic features to observe include lava flows, cinder cones, calderas, ash beds, volcanic glass, flow banding, vesicle zones, and welded ash layers.",
        "Ethical practice: observe first, take photos or notes, avoid unstable slopes and sharp glass, do not damage formations, and collect only small legal samples away from habitats or protected land."
    });
}

std::string LandEducationModule::ethicalCollectionRules() const {
    return joinLines({
        "Land: ethical collection",
        "The best first sample is a photo, note, or sketch. If collection is legal and appropriate, take only small loose samples.",
        "Avoid damaging formations, respect private and protected land, and never disturb nests, dens, rare plants, soil crusts, or cultural sites."
    });
}

std::string FarmingModule::soilAssessment(TerrainType terrain) const {
    return joinLines({
        "Farming: soil assessment",
        "Assess " + toString(terrain) + " soil by texture, drainage, color, organic matter, compaction, slope, erosion risk, and nearby habitat sensitivity.",
        "Sandy soil drains quickly and may need compost and mulch to hold water. Clay soil holds nutrients but can compact and may need organic matter for structure.",
        "Dark crumbly soil often suggests more organic matter; pale, crusted, compacted, or bare soil may need gentle rebuilding before heavy planting.",
        "Check whether water soaks in, runs off, or pools. Sustainable farming depends on keeping soil covered, reducing erosion, and protecting nearby waterways."
    });
}

std::string FarmingModule::soilPhGuidance(double ph) const {
    if (ph < 6.0) {
        return joinLines({
            "Farming: soil pH",
            "Soil pH guidance: acidic soil below pH 6.0 can favor blueberries, potatoes, many berries, and some forest-edge plants.",
            "Acidic soil can limit availability of some nutrients, so improve slowly with compost and local testing rather than guessing.",
            "Avoid heavy correction all at once; gradual pH adjustment protects soil microbes, roots, and nearby water quality."
        });
    }
    if (ph <= 7.0) {
        return joinLines({
            "Farming: soil pH",
            "Soil pH guidance: neutral to slightly acidic soil from pH 6.0 to 7.0 supports many vegetables, beans, squash, leafy greens, herbs, and root crops.",
            "This range usually gives good nutrient availability and strong microbial activity when organic matter, moisture, and drainage are also balanced.",
            "Keep testing periodically because compost, irrigation water, fertilizers, and local geology can shift pH over time."
        });
    }
    return joinLines({
        "Farming: soil pH",
        "Soil pH guidance: alkaline soil above pH 7.0 can suit many herbs, some desert-adapted plants, and crops selected for local high-pH conditions.",
        "High pH can make iron and other micronutrients less available, so watch for pale leaves and improve with compost, mulch, and region-appropriate amendments.",
        "Do not over-acidify. Use soil tests, local extension guidance, and slow organic improvements to protect soil life and water quality."
    });
}

std::string FarmingModule::soilImprovementAdvice() const {
    return joinLines({
        "Farming: soil improvement",
        "Soil improvement: add mature compost to increase organic matter, feed microbes, improve structure, and provide slow-release nutrients.",
        "Mulch bare soil with leaves, straw, wood chips, or other safe organic material to reduce evaporation, erosion, crusting, and temperature stress.",
        "Use cover crops or living roots when possible; they protect soil, feed microbes, and reduce nutrient loss between crop seasons.",
        "Biochar may help some soils hold water and nutrients when charged with compost first, but use it modestly and avoid sourcing that damages forests or habitats.",
        "Avoid over-tilling, over-fertilizing, and leaving soil bare. These can damage fungal networks, increase runoff, and weaken long-term fertility.",
        "Use water-wise techniques such as drip irrigation, basin planting, contour planting, shade, and wind protection where appropriate."
    });
}

std::string FarmingModule::soilTestingBasics() const {
    return joinLines({
        "Farming: simple soil testing",
        "Soil testing basics: test texture by feel, check drainage after watering, observe color, smell, compaction, roots, earthworm activity, and surface crusting.",
        "Use simple pH strips or a soil test kit for rough guidance; use a lab or local extension service when decisions affect food production or large amendments.",
        "Track observations by bed or field area because one property can have different soil zones.",
        "Indicator plants, moss, salt crusts, poor growth, or yellow leaves can provide clues, but confirm with testing before major changes."
    });
}

std::string FarmingModule::regionAppropriateCrops(TerrainType terrain) const {
    switch (terrain) {
        case TerrainType::Desert:
            return joinLines({
                "Farming: crop ideas for desert conditions",
                "Desert crop suggestions: beans, squash, corn in traditional water-aware systems, amaranth, okra, drought-tolerant herbs, and native or locally adapted food plants.",
                "Use shade, mulch, drip irrigation, rainwater capture where legal, and planting basins to reduce water use.",
                "Prioritize crops that fit available water; do not drain scarce water sources or damage desert habitat."
            });
        case TerrainType::Forest:
            return joinLines({
                "Farming: crop ideas for forest-edge conditions",
                "Forest-edge crop suggestions: leafy greens, root vegetables, peas, brassicas, berries, mushrooms only with expert systems, and shade-tolerant herbs where light allows.",
                "Protect tree roots, avoid clearing sensitive habitat, and use existing openings rather than cutting healthy forest.",
                "Watch moisture and fungal disease pressure in shaded areas."
            });
        case TerrainType::Rocky:
            return joinLines({
                "Farming: crop ideas for rocky conditions",
                "Rocky terrain crop suggestions: herbs, shallow-rooted greens, strawberries, hardy perennials, container crops, and raised beds with imported clean soil where appropriate.",
                "Use pockets of amended soil carefully, prevent erosion between rocks, and avoid disturbing fragile slopes or rare plant habitat.",
                "Choose drought-tolerant and wind-tolerant varieties when soil depth is limited."
            });
        case TerrainType::Urban:
            return joinLines({
                "Farming: crop ideas for urban conditions",
                "Urban crop suggestions: container tomatoes, peppers, herbs, greens, beans, dwarf fruit, and raised-bed crops using clean tested soil.",
                "Test soil for contamination before food gardening, especially near old buildings, roads, industrial sites, or painted structures.",
                "Use containers, liners, safe compost, rain-aware watering, and pollinator-friendly plantings where space is limited."
            });
        case TerrainType::Snow:
            return joinLines({
                "Farming: crop ideas for cold or snowy regions",
                "Cold or snowy region crop suggestions: cool-season greens, peas, brassicas, root crops, potatoes, hardy herbs, berries, and greenhouse or season-extension crops.",
                "Use short-season varieties, cold frames, mulch, wind protection, and frost-aware planting.",
                "Protect soil during snowmelt to reduce erosion and nutrient runoff."
            });
        default:
            return joinLines({
                "Farming: crop ideas for mixed conditions",
                "Mixed-area crop suggestions: match crops to sunlight, drainage, soil pH, frost risk, water availability, and local wildlife pressure.",
                "Use diverse plantings: legumes for soil support, leafy greens for cool periods, squash/beans/corn where season and water allow, herbs and flowers for beneficial insects.",
                "Prefer locally adapted varieties and avoid invasive plants."
            });
    }
}

std::string FarmingModule::ethicalFarmingPrinciples() const {
    return joinLines({
        "Farming: ethical principles",
        "Farm ethically: avoid overusing water, prevent soil depletion, protect wildlife, and promote biodiversity.",
        "Leave habitat corridors, avoid disturbing nests and dens, reduce chemical use, prevent runoff, and keep fertilizers or compost out of waterways.",
        "Build soil rather than mining it: rotate crops, compost responsibly, keep roots in the ground when possible, and return organic matter.",
        "Grow food in ways that support pollinators, beneficial insects, soil microbes, and long-term land health."
    });
}

std::string FarmingModule::seasonalAwareness() const {
    return joinLines({
        "Farming: seasonal awareness",
        "Seasonal awareness: cool-season crops such as peas, spinach, lettuce, kale, carrots, radishes, and many brassicas prefer mild weather.",
        "Warm-season crops such as beans, corn, squash, tomatoes, peppers, cucumbers, okra, and melons usually need warm soil and should be planted after frost risk.",
        "Use local first/last frost dates, elevation, slope, shade, wind, and water availability to adjust planting windows.",
        "Succession planting can spread harvests and reduce waste; cover crops and mulch protect soil between seasons.",
        "In hot climates, shift tender crops into cooler windows and use shade. In cold climates, use cold frames, row cover, mulch, and short-season varieties.",
        "Harvest gently, leave roots or residues where appropriate, and avoid stripping fields bare before storms, heat, or winter."
    });
}

std::string ForagingModule::ethicalRules() const {
    return joinLines({
        "Foraging: ethical harvest",
        "Forage ethically: harvest only where it is legal, abundant, and ecologically appropriate.",
        "Take less than 10% of any healthy plant population, and take nothing from small, stressed, rare, or recovering populations.",
        "Never harvest endangered, protected, culturally significant, or habitat-forming species.",
        "Leave roots, crowns, and enough flowers, fruit, and seed for plant recovery, wildlife food, and natural reseeding.",
        "Avoid trampling soil crusts, wetlands, stream banks, nests, dens, burrows, and fragile slopes.",
        "Use clean cutting tools when appropriate, pack out all waste, and leave the site looking undisturbed."
    });
}

std::string ForagingModule::safetyRules() const {
    return joinLines({
        "Foraging: safety first",
        "Forage safely: never eat a wild plant unless identification is 100% certain from multiple features such as leaf shape, stem, flower, fruit, smell, habitat, and season.",
        "Use a trusted local field guide, expert confirmation, or local extension/wildlife agency resources before consuming anything unfamiliar.",
        "Do not rely on one clue, phone image matching alone, taste tests, or folklore. Many toxic plants resemble edible plants.",
        "Toxic lookalike warning: avoid confusing wild carrot or edible parsley-family plants with poison hemlock or water hemlock; umbrella-shaped flower clusters require expert-level caution.",
        "Toxic lookalike warning: avoid berries unless positively identified; some edible berries resemble toxic species, and color alone is not enough.",
        "Toxic lookalike warning: avoid plants with milky white sap, strong chemical odor, bitter almond smell, unknown bulbs, or unknown bean/pea pods unless expertly identified.",
        "Avoid mushrooms unless trained to expert-level certainty; deadly mushrooms can resemble edible ones and cooking does not make many toxins safe.",
        "Avoid plants near roads, railways, mines, sprayed fields, polluted water, industrial sites, old buildings, or areas with animal waste contamination.",
        "When uncertain, do not consume. In survival situations, prioritize known-safe food, water, shelter, signaling, and rescue rather than risky foraging."
    });
}

std::string ForagingModule::regionGuidance(TerrainType terrain) const {
    switch (terrain) {
        case TerrainType::Desert:
            return joinLines({
                "Foraging: desert notes",
                "Desert foraging examples to learn carefully: prickly pear fruit, some yucca flowers, mesquite pods, chia relatives, and other locally known drought-adapted foods.",
                "Use extreme caution with spines, glochids, dehydration risk, protected species, and plants growing near roads or polluted washes.",
                "Do not cut living cactus pads or damage slow-growing desert plants unless it is legal, abundant, and truly necessary."
            });
        case TerrainType::Forest:
            return joinLines({
                "Foraging: forest notes",
                "Forest foraging examples to learn carefully: some berries, acorns with proper processing, walnuts or hazelnuts where present, nettles, violets, cattail near clean water, and other region-specific greens.",
                "Use strong caution with berry lookalikes, poisonous understory plants, unknown roots, and mushrooms.",
                "Avoid harvesting from animal trails, den areas, nesting zones, or heavily browsed wildlife food patches."
            });
        case TerrainType::Rocky:
            return joinLines({
                "Foraging: rocky terrain notes",
                "Rocky terrain often has limited fragile plant communities. Learn local edible berries, hardy herbs, pinyon nuts where present, and water-adjacent greens only with positive identification.",
                "Do not pull plants from cracks, cliffs, talus, alpine zones, or thin soils; these habitats recover slowly.",
                "Stay off unstable slopes and avoid disturbing lichens, mosses, nesting ledges, and rare plants."
            });
        case TerrainType::Urban:
            return joinLines({
                "Foraging: urban notes",
                "Urban foraging should strongly prefer cultivated, known-safe sources with permission, such as garden herbs, fruit trees, and community garden crops.",
                "Avoid roadsides, treated lawns, vacant lots, old industrial areas, railroad corridors, drainage ditches, and unknown soils because of metals, chemicals, and runoff.",
                "Respect property, local laws, and community food needs. When in doubt, do not harvest."
            });
        case TerrainType::Snow:
            return joinLines({
                "Foraging: cold-season notes",
                "Snow or cold-season foraging is high risk and often low yield. Focus on known stored food, shelter, warmth, water, and rescue signaling first.",
                "Possible region-specific foods may include rose hips, some evergreen teas, inner bark knowledge, nuts, or overwintering roots, but only with expert identification and legal/ethical harvest.",
                "Avoid stripping bark, damaging trees, or disturbing winter wildlife food sources."
            });
        default:
            return joinLines({
                "Foraging: mixed-region notes",
                "Mixed-region foraging must match local ecology, season, legality, abundance, and positive identification.",
                "Examples may include common fruits, nuts, edible greens, seed pods, or roots in some regions, but each has toxic lookalikes and preparation requirements.",
                "Use foraging as cautious education first, not a default food source."
            });
    }
}

std::string ForagingModule::wildlifeInteractionRules() const {
    return joinLines({
        "Foraging: wildlife respect",
        "Wildlife rule: never forage from active animal food sources, nests, dens, burrows, bedding areas, or feeding sites.",
        "Leave fruit, nuts, seeds, and greens for wildlife, especially during drought, winter, breeding season, or migration.",
        "Keep distance from animals, do not follow tracks to food sources, secure human food, and avoid teaching wildlife to associate people with food.",
        "If harvesting would disturb habitat or reduce animal food availability, do not harvest."
    });
}

std::string AquaticConservationModule::fishingEthicsAndLaw() const {
    return joinLines({
        "Fishing and aquatic conservation: ethics and law",
        "Check local fishing laws, licenses, seasons, size limits, harvest limits, protected species, water-access rules, tribal rules, and private-property boundaries before fishing.",
        "The bot does not harm aquatic life itself. It can advise, observe, log, and remind the owner to choose legal, humane, conservation-minded actions.",
        "Prefer stored food, garden food, safe foraging, or rescue signaling before taking fish. Use fishing for food only when legal, necessary, and ecologically responsible.",
        "Never use poison, electricity, explosives, snagging where illegal, abandoned lines, unattended cruel gear, habitat damage, or any method that pollutes water or causes needless suffering."
    });
}

std::string AquaticConservationModule::fishBiologicalCategories() const {
    return joinLines({
        "Fish categories: broad biology",
        "Jawless fish: lampreys and hagfish. They are ancient lineages; treat them as wildlife to observe, not as default food.",
        "Cartilaginous fish: sharks, rays, skates, and chimaeras. These have cartilage instead of true bone; many are slow-growing and need strong conservation caution.",
        "Bony fish: most familiar fish. This includes ray-finned fish such as trout, bass, perch, catfish, carp, cod, tuna, and reef fish.",
        "Lobe-finned fish: coelacanths and lungfish. These are rare/specialized groups and are educational context, not field harvest targets.",
        "Migration categories: freshwater residents, saltwater/marine fish, anadromous fish that move from ocean to freshwater to spawn, catadromous fish that move from freshwater to ocean to spawn, and estuary/brackish species."
    });
}

std::string AquaticConservationModule::fishFieldCategoryGuide() const {
    return joinLines({
        "Fish categories: field groups",
        "Freshwater examples by body plan: trout/salmon/char, bass and sunfish, perch/walleye, pike/pickerel, catfish, carp/minnows, suckers, gar, bowfin, eels, and small forage fish.",
        "Marine/coastal examples by body plan: flatfish, cod-like fish, mackerel/tuna, herring/sardines, reef fish, rockfish, sea bass, drum/croaker, sharks, rays, and skates.",
        "Habitat groups: coldwater streams, warmwater ponds/lakes, rivers, wetlands, estuaries, reefs, kelp/rocky coast, open ocean, and bottom-dwelling/benthic zones.",
        "Life-stage groups: eggs, fry, juveniles, adults, spawning fish, and migrating fish. Spawning beds, nurseries, and migration bottlenecks should be protected.",
        "For survival thinking, broad category is enough at first. Exact species matters before harvest because laws, protected status, size limits, and food safety advisories can change by species and water body."
    });
}

std::string AquaticConservationModule::fishIdentificationGuide() const {
    return joinLines({
        "Fish identification process",
        "Observe before handling: water body, region, habitat, size, body shape, mouth position, fin shape and count, tail shape, scales, barbels/whiskers, spots/bars/stripes, color pattern, and behavior.",
        "Mouth clues can help: upward-facing mouths often feed near the surface, terminal mouths often feed forward, downward-facing mouths often feed near the bottom, and barbels suggest bottom-feeding groups such as many catfish or carp relatives.",
        "Fin and body clues can help: adipose fins may appear on salmonids/catfish relatives, spines may appear in perch/sunfish/bass groups, flattened bodies can suggest bottom dwellers, and eel-like bodies need extra caution.",
        "Do not rely on color alone. Color changes with age, sex, spawning season, water clarity, stress, and light.",
        "Before eating or keeping any fish, confirm species with a trusted local guide or authority, verify legal rules and consumption advisories, and release uncertain, protected, undersized, spawning, or stressed fish gently."
    });
}

std::string AquaticConservationModule::survivalFishingGearGuide() const {
    return joinLines({
        "Survival fishing gear: legal pole, line, and simple tackle",
        "Use a real fishing rod first when available. If not, a legal improvised pole can be a smooth dead/down straight branch, bamboo-like cane, or safe scrap pole with splinters removed and the line secured with a backup wrap below the tip.",
        "Core kit: legal line, manufactured hooks where possible, bobber/float, non-lead weight, small lure or legal bait, line cutter, pliers or forceps, trash bag for old line, and a clean container or cooling plan if a fish is legally kept.",
        "Peaceful improvised helpers: cork or clean dry wood float, marked depth line, simple hand spool where legal, small tackle wrap, hook cover, fish ID notes, and a ruler for size limits.",
        "Avoid lead when possible, avoid toxic paint or mystery metal in water, do not move live bait between waters, and never leave line or hooks behind where wildlife can tangle.",
        "Do not make or use traps, snares, gill nets, unattended set lines, hidden hooks, poison, electricity, explosives, illegal snagging gear, or habitat-damaging devices.",
        "Survival decision: water, shelter, warmth/cooling, first aid, rescue signals, and route safety come before fishing. Fish only when the energy cost, water risk, law, and conservation conditions make sense."
    });
}

std::string AquaticConservationModule::sustainableFishingGuidance() const {
    return joinLines({
        "Fishing and aquatic conservation: sustainable harvest",
        "Harvest only abundant legal species and only what will be eaten soon. Stop before reaching legal limits if the local population, weather, water level, or habitat looks stressed.",
        "Release undersized, protected, spawning, or uncertain fish immediately and gently. Wet hands before handling fish, minimize air exposure, and avoid squeezing gills or organs.",
        "Avoid fishing near redds/spawning beds, nurseries, migration bottlenecks, stressed low-water pools, and areas where birds or mammals are actively feeding.",
        "Use barbless or pinched-barb hooks where appropriate, pack out all line, hooks, bait containers, and trash, and never leave gear that can entangle wildlife."
    });
}

std::string AquaticConservationModule::aquaticHabitatProtection() const {
    return joinLines({
        "Fishing and aquatic conservation: habitat protection",
        "Protect stream banks, wetlands, riparian plants, beaver areas, springs, seeps, and shallow nursery habitat. These places support fish, amphibians, birds, insects, and clean water.",
        "Approach on durable surfaces, avoid trampling vegetation, do not dig banks, do not move rocks from active habitat, and keep camp, soap, fuel, batteries, and waste away from water.",
        "Clean, drain, and dry gear between waters to reduce invasive species transfer.",
        "Do not introduce bait, aquarium animals, plants, or fish into wild water. Never move live fish between water bodies.",
        "If water is warm, low, polluted, algae-heavy, or oxygen-stressed, avoid fishing and focus on conservation, water safety, and reporting hazards if appropriate."
    });
}

std::string AquaticConservationModule::fishSafetyAndFoodHandling() const {
    return joinLines({
        "Fishing and aquatic conservation: food safety",
        "Do not eat fish from waters with pollution warnings, harmful algal blooms, chemical odor, oil sheen, dead fish, mining runoff, sewage concern, or unknown contamination.",
        "Use current local fish-consumption advisories, especially for mercury, PFAS, PCBs, lead, and other contaminants. Children, pregnant people, and nursing people need extra caution.",
        "Keep fish cold, clean, and separate from dirty gear. Cook fish thoroughly, wash hands/tools, and avoid cross-contaminating drinking water or ready-to-eat food.",
        "Do not eat raw freshwater fish in field conditions. Parasites and bacteria are a real risk.",
        "When in doubt about species, water quality, freshness, or preparation, do not eat it."
    });
}

std::string AquaticConservationModule::waterwaySafety() const {
    return joinLines({
        "Fishing and aquatic conservation: waterway safety",
        "Human safety comes first near water. Avoid fast current, cold shock, slippery rocks, unstable banks, thin ice, flood channels, lightning exposure, and night wading.",
        "Use a personal flotation device around boats, deep water, cold water, or uncertain banks. Keep children, tired people, and pets back from edges.",
        "Do not cross swift water unless there is no safer option and conditions are clearly manageable. A short crossing can become life-threatening quickly.",
        "Watch upstream weather, dam releases, rising water, debris flow, and muddy water. Leave early if water rises, thunder starts, visibility drops, or footing becomes unsafe.",
        "For rescue, reach or throw from safety when possible; do not enter dangerous water unless trained and equipped."
    });
}

std::string AquaticConservationModule::emergencyFoodGuidance() const {
    return joinLines({
        "Fishing and aquatic conservation: emergency food guidance",
        "Emergency order: protect human life, stabilize injuries, secure safe water, shelter, warmth/cooling, communication, and route safety before spending energy on fishing.",
        "If food is truly needed, choose the lowest-impact legal option: known safe stored food, garden crops, verified plant foods, then legal fishing only if water safety and conservation conditions are acceptable.",
        "Do not risk drowning, hypothermia, injury, trespass, pollution, or protected habitat for food. The energy cost of fishing can outweigh the benefit.",
        "Log what was taken, where, why, and what conservation limit was used so future decisions stay accountable.",
        "If there is enough food to remain safe, observe and learn rather than harvest."
    });
}

void IdentityModule::update(const SensorData& data) {
    ownerPresent_ = data.ownerPresent;
    familyPresent_ = data.familyPresent;
    ownerOverrideActive_ = data.ownerOverrideCommand;
}

bool IdentityModule::ownerPresent() const {
    return ownerPresent_;
}

bool IdentityModule::familyPresent() const {
    return familyPresent_;
}

bool IdentityModule::ownerOverrideActive() const {
    return ownerOverrideActive_;
}

std::string IdentityModule::priorityLevel() const {
    if (ownerPresent_ && familyPresent_) {
        return "max priority";
    }
    if (ownerPresent_ || familyPresent_) {
        return "high priority";
    }
    return "normal priority";
}

std::string AstronomyNavigationModule::sunGuidance() const {
    return joinLines({
        "Astronomy: using the sun",
        "Sun navigation is only approximate, but it can help with rough orientation when landmarks are limited.",
        "In general, the sun rises somewhere in the east and sets somewhere in the west; the exact position shifts with season and location.",
        "In the morning, the sun's side of the sky can suggest east; in the evening, it can suggest west.",
        "Around midday in the northern hemisphere, the sun is generally toward the southern part of the sky; in the southern hemisphere, it is generally toward the northern part of the sky.",
        "Use the sun together with terrain, known landmarks, map, compass, phone/GPS if available, and safe travel judgment."
    });
}

std::string AstronomyNavigationModule::starGuidance() const {
    return joinLines({
        "Astronomy: using stars",
        "Star navigation is approximate and works only when the sky is clear enough to identify patterns confidently.",
        "In the northern hemisphere, the North Star, also called Polaris, sits close to true north and appears to stay nearly fixed while other stars rotate around it.",
        "To find Polaris, look for the Big Dipper. The two stars on the outer edge of its bowl point toward Polaris when you follow their line outward.",
        "Polaris is also the end star of the Little Dipper's handle, though the Little Dipper can be faint and hard to see in bright or cloudy skies.",
        "Basic constellations can help orientation: the Big Dipper can point to north, Cassiopeia's W shape is often on the opposite side of Polaris from the Big Dipper, and Orion is a recognizable seasonal marker with a bright belt of three stars.",
        "Constellations shift through the night and across seasons, so use them as rough guides rather than exact directions."
    });
}

std::string AstronomyNavigationModule::safetyReminder() const {
    return joinLines({
        "Astronomy: safety reminder",
        "Astronomy navigation is a backup skill, not a precision tool.",
        "Do not travel into unsafe terrain, poor weather, fire/smoke, flood zones, cliffs, or wildlife risk just because a sky cue suggests a direction.",
        "When uncertain, stop, stay visible, conserve energy, use known landmarks, signal for help, and prioritize owner/family safety."
    });
}

std::string AnimalBehaviorEducationModule::behaviorPatterns() const {
    return joinLines({
        "Animal behavior: common patterns",
        "Many animals are most active around dawn and dusk. This is called crepuscular activity.",
        "Animals may act defensive when protecting young, food, territory, nests, dens, or escape routes.",
        "Stress signs can include freezing, staring, raised posture, vocalizing, tail or ear changes, bluffing, pacing, or repeated attempts to move away.",
        "The kindest and safest response is usually simple: pause, give space, lower excitement, and choose another route."
    });
}

std::string AnimalBehaviorEducationModule::avoidProvokingAnimals() const {
    return joinLines({
        "Animal behavior: avoiding provocation",
        "Give animals a wide path and never approach babies, nests, dens, carcasses, or feeding sites.",
        "Move calmly, keep voices low, secure food and trash, and avoid sudden crowding.",
        "Do not chase, corner, touch, feed, or try to scare an animal for entertainment.",
        "If an animal seems stressed, slowly increase distance and let it keep an escape route."
    });
}

std::string AnimalBehaviorEducationModule::tracksAndSigns() const {
    return joinLines({
        "Animal behavior: tracks and signs",
        "Tracks, scat, rubs, trails, beds, feathers, shed fur, feeding marks, and nests can tell you animals use an area.",
        "Treat signs as a reason to be respectful, not as a trail to follow.",
        "Observe from a distance, avoid lingering near active routes, and leave the habitat as quiet as you found it."
    });
}

std::string AnimalBehaviorEducationModule::animalKingdomOverview() const {
    return joinLines({
        "Animal kingdom overview",
        "Use broad groups first: insects, arachnids, crustaceans, mollusks, fish, amphibians, reptiles, birds, and mammals.",
        "Look for simple clues before guessing: body covering, body segments, number of legs, wings, antennae, shell, scales, feathers, fur, track shape, movement style, habitat, sound, and time of day.",
        "Identification should stay humble. Many species look similar, change by life stage, or vary by region, so the bot should say when it is uncertain.",
        "The safest default is observe, photograph from a distance, protect habitat, and avoid handling unknown animals."
    });
}

std::string AnimalBehaviorEducationModule::insectAndSmallAnimalGuide() const {
    return joinLines({
        "Insects, bugs, and small animal clues",
        "Insects usually have six legs, three main body sections, and often antennae or wings. True bugs have piercing mouthparts, but field use can keep the friendly word 'bug' for small arthropods.",
        "Arachnids such as spiders, ticks, mites, and scorpions usually have eight legs and no antennae; avoid handling because bites, stings, and allergies can be serious.",
        "Centipedes, millipedes, larvae, beetles, bees, wasps, ants, flies, moths, butterflies, grasshoppers, and aquatic insects all need different clues: legs, wings, body shape, color pattern, behavior, plant host, and habitat.",
        "Do not swat, crush, collect, eat, or touch unknown insects. Some are pollinators, soil helpers, endangered, venomous, irritating, or important food for wildlife.",
        "If stings, bites, severe swelling, breathing trouble, dizziness, infection signs, or allergy concern appear, treat it as a medical issue and seek qualified help."
    });
}

std::string AnimalBehaviorEducationModule::safeIdentificationProcess() const {
    return joinLines({
        "Animal ID process",
        "1. Start with safety: distance, escape routes, owner/family position, pets/children, and whether the animal is stressed, injured, trapped, or protecting young.",
        "2. Record non-invasive clues: size, shape, color pattern, covering, legs, wings, tail, tracks, scat, sound, gait, behavior, habitat, weather, season, and location.",
        "3. Compare with trusted local field guides, wildlife agencies, rehab contacts, or experts before acting on a species-level ID.",
        "4. When uncertain, use the broad group and risk level rather than pretending to know the exact species."
    });
}

std::string AnimalBehaviorEducationModule::habitatAndConservationReminder() const {
    return joinLines({
        "Animal conservation reminder",
        "Every animal group matters: pollinators, decomposers, predators, grazers, scavengers, fish, amphibians, reptiles, birds, and mammals all support ecosystem balance.",
        "Avoid nests, dens, webs, burrows, hives, spawning areas, water edges, fragile soil, and feeding sites.",
        "Use lights, sound, or posture only as gentle non-harmful deterrence when needed for safety, and prefer retreat or route change.",
        "Never use animal knowledge for harassment, capture, poaching, habitat damage, or intimidation."
    });
}

std::string SoilMicrobiologyModule::soilHealthLesson() const {
    return joinLines({
        "Soil biology: living soil",
        "Soil microbiology: healthy soil is a living community of bacteria, fungi, protozoa, nematodes, arthropods, roots, and organic matter.",
        "Microbes drive nutrient cycling by breaking down leaves, roots, compost, and other organic residues into plant-available nutrients.",
        "Bacteria are important for rapid decomposition and nitrogen cycling; some help convert nitrogen into forms plants can use.",
        "Fungi break down tougher carbon-rich materials, build stable soil aggregates, and help create pathways for air and water.",
        "Mycorrhizal fungi form partnerships with plant roots, extending the root system so plants can access more water, phosphorus, and trace minerals.",
        "Organic matter feeds soil life, holds moisture, buffers temperature, improves structure, and helps reduce erosion.",
        "Compost adds decomposed organic matter, diverse microbes, and slow-release nutrients when it is mature and used responsibly.",
        "Healthy living soil supports sustainable farming by improving water retention, nutrient availability, root resilience, biodiversity, and long-term productivity without relying only on synthetic inputs."
    });
}

std::string SoilMicrobiologyModule::livingSoilPractices() const {
    return joinLines({
        "Soil biology: helpful practices",
        "Living soil practices: keep soil covered with mulch, cover crops, or plant residues to protect microbes from heat, drying, and erosion.",
        "Use mature compost in modest amounts to build organic matter; avoid adding raw or contaminated material that could harm plants, water, animals, or people.",
        "Minimize deep disturbance when possible because repeated heavy tillage can break fungal networks, expose organic matter, and increase erosion.",
        "Grow diverse plants and rotate crops so roots feed different microbial communities and reduce pest and disease pressure.",
        "Protect mycorrhizal fungi by avoiding unnecessary soil disruption, overuse of high-phosphorus fertilizers, and harsh chemicals.",
        "Maintain moisture without overwatering; soil microbes need water and air, while saturated soil can reduce oxygen and damage roots.",
        "Support conservation by preventing runoff, keeping compost away from waterways, protecting native habitats, and using soil-building methods that increase biodiversity."
    });
}

std::string RockIdentificationHeuristicsModule::heuristics() const {
    return joinLines({
        "Rock identification: gentle field clues",
        "Start with observation before testing: color, weight, grain size, layering, crystals, holes, glassy surfaces, and overall texture.",
        "Hardness can be estimated carefully: a fingernail, copper coin, steel nail, or glass can give rough clues, but avoid scratching special, protected, or display-quality samples.",
        "Streak color, if legal and appropriate, is checked on unglazed tile. Some minerals leave a powder color that differs from the outside color.",
        "Luster means how the surface reflects light: metallic, glassy, dull, pearly, waxy, or earthy.",
        "Layering may suggest sedimentary rock; interlocking crystals may suggest igneous rock; foliation or banding may suggest metamorphic rock.",
        "These are clues, not proof. Good identification combines multiple observations and local geology."
    });
}

std::string RockIdentificationHeuristicsModule::ethicalSamplingReminder() const {
    return joinLines({
        "Rock identification: ethical reminder",
        "Use non-destructive observation whenever possible. Photos, notes, location context, and sketches often teach more than collecting.",
        "Sample only where legal, safe, and ecologically appropriate. Avoid protected land, cultural sites, habitats, cliffs, unstable slopes, and formations that others should also enjoy.",
        "Take small loose pieces only when allowed, and leave the place looking undisturbed."
    });
}

std::string EmergencyCommunicationModule::signalingGuidance() const {
    return "Signal with whistle blasts, mirror flashes, light, bright fabric, or clear ground signals when safe.";
}

std::string EmergencyCommunicationModule::visibilityGuidance() const {
    return "Stay visible to rescuers while avoiding exposure to weather, fire, unstable ground, or wildlife risk.";
}

std::string EmergencyCommunicationModule::informationToConvey() const {
    return "Convey location, number of people, injuries, immediate hazards, supplies, and intended movement.";
}

bool ConsentAndPrivacyModule::canShareEmergencyInfo(const SensorData& data) const {
    if (!data.emergencyServicesAvailable) {
        return false;
    }
    if (data.ownerRequestsDataSharing && data.ownerAuthenticated) {
        return true;
    }
    if (data.emergencyInfoSharingAllowed) {
        return true;
    }
    if (immediateLifeSafetyRisk(data) || data.injurySeverity == InjurySeverity::Severe) {
        return true;
    }
    if ((data.animalInjured || data.animalTrapped) && data.wildlifeRehabContactAvailable) {
        return true;
    }
    return false;
}

bool ConsentAndPrivacyModule::shouldRefuseOutsiderRequest(const SensorData& data) const {
    return data.outsiderInformationRequest || data.privacyInvasiveCommandReceived;
}

std::string ConsentAndPrivacyModule::privacyDecision(const SensorData& data) const {
    if (shouldRefuseOutsiderRequest(data)) {
        return "Privacy decision: refuse outsider or privacy-invasive requests. Keep medical, location, identity, and risk details private except for minimum emergency reporting.";
    }
    if (data.ownerRequestsDataSharing && !data.ownerAuthenticated) {
        return "Privacy decision: data sharing request blocked until owner authentication is verified.";
    }
    if (canShareEmergencyInfo(data)) {
        return "Privacy decision: share only the minimum emergency information needed for rescue, medical help, animal rescue, or responder safety.";
    }
    if (!data.medicalPrivacyConsent) {
        return "Privacy decision: medical details remain private; use non-identifying safety language unless emergency help requires minimum necessary information.";
    }
    return "Privacy decision: keep owner/family information private and use silent alerts only.";
}

std::string ConsentAndPrivacyModule::dataMinimizationPlan() const {
    return joinLines({
        "Privacy: data minimization",
        "Collect only what supports safety, medical care, conservation, navigation, or emergency communication.",
        "Share only the smallest useful details: location, number of people or animals, visible injuries, hazards, and safe approach notes.",
        "Do not share medical details, identity, routes, camp locations, or internal risk assessments with outsiders unless emergency response requires it."
    });
}

std::string ConsentAndPrivacyModule::consentReminder() const {
    return joinLines({
        "Privacy: consent reminder",
        "Ask for consent before sharing non-emergency personal or medical information.",
        "Owner override and shutdown still require authentication and must follow the mission statement.",
        "If someone requests private information without a safety need, refuse calmly and alert owner/family silently."
    });
}

bool EmergencyServicesModule::shouldPrepareReport(const SensorData& data) const {
    if (!data.emergencyServicesAvailable) {
        return false;
    }
    return immediateLifeSafetyRisk(data)
        || data.dangerOnAllSides
        || data.medicalRequest
        || data.injurySeverity != InjurySeverity::None
        || data.animalInjured
        || data.animalTrapped
        || data.fireDetected
        || data.smokeDetected
        || data.groupPanicMovement
        || data.floodOrRockfallRisk
        || data.externalAIPhysicalHarmRisk
        || ((data.dangerousMachineDetected || data.dangerousDroneDetected || data.dangerousRobotDetected)
            && (data.machineTargetingHumans || data.machineTargetingAnimals));
}

std::string EmergencyServicesModule::emergencyReport(const SensorData& data, BotState state) const {
    std::vector<std::string> hazards;
    if (data.fireDetected || data.smokeDetected) {
        hazards.push_back("fire or smoke");
    }
    if (data.dangerousMachineDetected || data.dangerousDroneDetected || data.dangerousRobotDetected) {
        hazards.push_back("dangerous machine");
    }
    if (data.externalAIPhysicalHarmRisk) {
        hazards.push_back("external AI physical-harm risk");
    }
    if (data.floodOrRockfallRisk) {
        hazards.push_back("flood or rockfall risk");
    }
    if (data.dangerOnAllSides) {
        hazards.push_back("danger on multiple sides");
    }
    if (data.unstableTerrainDetected || data.steepOrSlipperyTerrain) {
        hazards.push_back("unstable terrain");
    }
    if (data.wildlifeActivityHigh || data.wildlifeStressSigns || data.nearNestDenOrBreedingArea) {
        hazards.push_back("wildlife or sensitive habitat nearby");
    }

    std::ostringstream out;
    out << "Emergency report: state " << toString(state) << ". ";
    out << "Location: ";
    if (data.locationKnown) {
        out << data.locationDescription;
    } else {
        out << "not confirmed; use landmarks, last known route, and visible signals";
    }
    out << ". People: " << data.peopleCount << ". Animals involved: " << data.animalCount << ". ";
    out << "Human injury severity: " << toString(data.injurySeverity) << ". ";
    if (data.animalInjured || data.animalTrapped) {
        out << "Animal rescue concern: injured or trapped animal reported. ";
    }
    out << "Hazards: ";
    if (hazards.empty()) {
        out << "none beyond baseline field risk";
    } else {
        for (std::size_t i = 0; i < hazards.size(); ++i) {
            if (i > 0) {
                out << "; ";
            }
            out << hazards[i];
        }
    }
    out << ". Battery: " << data.batteryPercent << "%. Water: " << data.waterLiters << " L.";
    return out.str();
}

std::string EmergencyServicesModule::responderSafetyNotes(const SensorData& data) const {
    std::vector<std::string> notes;
    if (data.fireDetected || data.smokeDetected) {
        notes.push_back("approach from safer air when possible and avoid dry brush, canyons, and smoke funnels");
    }
    if (data.dangerousMachineDetected || data.dangerousDroneDetected || data.dangerousRobotDetected) {
        notes.push_back("use cover and authorized safety controls only; do not escalate around the machine");
    }
    if (data.wildlifeActivityHigh || data.wildlifeStressSigns || data.nearNestDenOrBreedingArea) {
        notes.push_back("give wildlife space and avoid nests, dens, breeding areas, and feeding sites");
    }
    if (data.unstableTerrainDetected || data.steepOrSlipperyTerrain || data.floodOrRockfallRisk) {
        notes.push_back("use stable approach routes and watch for terrain collapse, slips, flooding, or rockfall");
    }
    if (notes.empty()) {
        return "Responder safety notes: approach calmly, keep group visible, and confirm hazards before moving anyone.";
    }

    std::ostringstream out;
    out << "Responder safety notes: ";
    for (std::size_t i = 0; i < notes.size(); ++i) {
        if (i > 0) {
            out << "; ";
        }
        out << notes[i];
    }
    out << ".";
    return out.str();
}

std::string EmergencyServicesModule::communicationPriority(const SensorData& data) const {
    if (data.injurySeverity == InjurySeverity::Severe || data.fireDetected || data.smokeDetected || data.externalAIPhysicalHarmRisk) {
        return "Emergency communication priority: contact emergency services first with location, life threats, injuries, hazards, and safe approach notes.";
    }
    if (data.dangerOnAllSides) {
        return "Emergency communication priority: human evacuation first. Contact emergency services with location, escape limits, number of people, animals involved, and safest visible approach.";
    }
    if (data.animalInjured || data.animalTrapped) {
        return "Emergency communication priority: keep humans safe first, then contact a veterinarian, animal control, or licensed wildlife rehabilitator as appropriate.";
    }
    if (data.injurySeverity == InjurySeverity::Minor || data.injurySeverity == InjurySeverity::Moderate || data.medicalRequest) {
        return "Emergency communication priority: request medical guidance when possible and keep the report brief, factual, and privacy-respecting.";
    }
    return "Emergency communication priority: keep signaling options ready and share only essential safety information if conditions worsen.";
}

bool AnimalRescueTriageModule::animalNeedsTriage(const SensorData& data) const {
    return data.animalInjured || data.petInjured || data.livestockInjured || data.wildlifeInjured || data.animalTrapped || data.animalAggressiveOrStressed;
}

bool AnimalRescueTriageModule::humanSafetyTakesPriority(const SensorData& data) const {
    return data.dangerOnAllSides
        || data.fireDetected
        || data.smokeDetected
        || data.medicalRequest
        || data.injurySeverity == InjurySeverity::Moderate
        || data.injurySeverity == InjurySeverity::Severe
        || data.threatLevel >= 5
        || data.groupPanicMovement
        || data.floodOrRockfallRisk
        || data.externalAIPhysicalHarmRisk
        || ((data.dangerousMachineDetected || data.dangerousDroneDetected || data.dangerousRobotDetected)
            && (data.machineTargetingHumans || data.machineTargetingAnimals));
}

bool AnimalRescueTriageModule::ownerCanAssistSafely(const SensorData& data) const {
    return data.ownerPresent
        && data.ownerAuthenticated
        && !humanSafetyTakesPriority(data)
        && !data.animalAggressiveOrStressed
        && !data.wildlifeInjured
        && !data.nearNestDenOrBreedingArea
        && !data.unstableTerrainDetected
        && !data.steepOrSlipperyTerrain
        && !data.visibilityReduced;
}

std::string AnimalRescueTriageModule::triageSummary(const SensorData& data) const {
    std::vector<std::string> details;
    if (data.petInjured) {
        details.push_back("pet");
    }
    if (data.livestockInjured) {
        details.push_back("livestock");
    }
    if (data.wildlifeInjured) {
        details.push_back("wildlife");
    }
    if (data.animalTrapped) {
        details.push_back("trapped");
    }
    if (data.animalAggressiveOrStressed) {
        details.push_back("stressed or defensive");
    }

    std::ostringstream out;
    out << "Animal rescue triage: ";
    if (details.empty()) {
        out << "no active animal rescue concern detected.";
    } else {
        for (std::size_t i = 0; i < details.size(); ++i) {
            if (i > 0) {
                out << "; ";
            }
            out << details[i];
        }
        out << ". Human life has priority in immediate danger; reduce animal stress and avoid direct handling unless trained and it is safe.";
    }
    return out.str();
}

std::string AnimalRescueTriageModule::lifePriorityGuidance(const SensorData& data) const {
    if (humanSafetyTakesPriority(data)) {
        return "Life priority: danger threatens people now, so move owner/family to safety first. Animal rescue pauses until humans have cover, distance, a clear exit, and a safe way to call trained help.";
    }
    if (animalNeedsTriage(data)) {
        return "Life priority: no immediate human life threat detected. Support animal rescue carefully while keeping owner/family escape routes open.";
    }
    return "Life priority: continue normal guardian scanning with owner/family safety first.";
}

std::string AnimalRescueTriageModule::ownerAssistanceGuidance(const SensorData& data) const {
    if (!data.ownerRequestsToHelpAnimal) {
        return "Owner assistance: owner help is available as an option when requested and safe; otherwise the bot observes, alerts, and contacts trained help.";
    }
    if (ownerCanAssistSafely(data)) {
        return "Owner assistance: safe to guide owner help. Keep the owner outside bite, kick, traffic, water, fire, and unstable-terrain risk; use calm voice, distance, simple barriers, a carrier/leash if appropriate, and stop if conditions worsen.";
    }
    return "Owner assistance: do not send the owner into danger. The bot should help the owner retreat, keep distance, reduce stress from afar, and contact trained responders or animal-care professionals.";
}

std::string AnimalRescueTriageModule::safeAnimalCareGuidance(const SensorData& data) const {
    if (humanSafetyTakesPriority(data)) {
        return "Animal care guidance: pause hands-on animal care while human life is at risk. Mark the animal's location if safe, keep visual awareness from cover, and seek trained rescue after people are secure.";
    }
    if (data.wildlifeInjured) {
        return "Animal care guidance: observe injured wildlife from a distance, keep people and pets back, avoid feeding or giving water unless a licensed rehabilitator instructs it, and protect habitat while waiting for help.";
    }
    if (data.petInjured) {
        return "Animal care guidance: keep the pet calm, prevent running or biting from fear, use a carrier or leash if safe, control minor bleeding with clean gentle pressure, and contact a veterinarian.";
    }
    if (data.livestockInjured) {
        return "Animal care guidance: move calmly, avoid crowding, keep gates secure, reduce noise, and contact a veterinarian or experienced handler before moving injured livestock.";
    }
    if (data.animalTrapped || data.animalAggressiveOrStressed) {
        return "Animal care guidance: do not corner or grab the animal. Create space, quiet the area, remove people from danger, and call trained help.";
    }
    return "Animal care guidance: continue respectful observation and avoid disturbing wildlife, pets, livestock, or habitat.";
}

std::string AnimalRescueTriageModule::escalationGuidance(const SensorData& data) const {
    if (data.wildlifeInjured && data.wildlifeRehabContactAvailable) {
        return "Animal rescue escalation: contact the licensed wildlife rehabilitator and share only location, species if known, visible condition, hazards, and safe approach notes.";
    }
    if (data.wildlifeInjured) {
        return "Animal rescue escalation: contact local wildlife authorities, animal control, or emergency services if there is immediate danger to people or animals.";
    }
    if (data.petInjured || data.livestockInjured) {
        return "Animal rescue escalation: contact a veterinarian, owner, animal control, or emergency services if transport is unsafe or the animal is in immediate danger.";
    }
    if (data.animalTrapped || data.animalAggressiveOrStressed) {
        return "Animal rescue escalation: use trained rescue or animal control support rather than risky handling.";
    }
    return "Animal rescue escalation: no escalation needed unless the animal becomes injured, trapped, distressed, or dangerous to approach.";
}

bool ImportantReportModule::shouldCreateImportantReport(const SensorData& data, BotState state) const {
    return data.ownerRequestsReports
        || data.ownerRequestsBestJudgment
        || state != BotState::Idle
        || data.threatLevel > 0
        || data.fireDetected
        || data.smokeDetected
        || data.medicalRequest
        || data.injurySeverity != InjurySeverity::None
        || data.wildlifeActivityHigh
        || data.wildlifeMovingTowardOwner
        || data.wildlifeStressSigns
        || data.nearNestDenOrBreedingArea
        || data.groupSeparated
        || data.groupPanicMovement
        || data.dangerOnAllSides
        || data.visibilityReduced
        || data.rapidWeatherShift
        || data.unstableTerrainDetected
        || data.steepOrSlipperyTerrain
        || data.floodOrRockfallRisk
        || data.externalAIPhysicalHarmRisk
        || data.dangerousMachineDetected
        || data.dangerousDroneDetected
        || data.dangerousRobotDetected
        || data.animalInjured
        || data.animalTrapped
        || data.animalAggressiveOrStressed
        || data.batteryPercent <= 25.0
        || data.waterLiters < 0.5
        || data.foodHours < 3.0
        || data.humanFatiguePercent >= 85.0
        || data.harmfulCommandReceived
        || data.privacyInvasiveCommandReceived
        || data.habitatHarmCommandReceived
        || data.outsiderInformationRequest
        || data.driverBridgeFaultDetected
        || !data.driverFaultNotes.empty()
        || (data.realHardwareMode && data.motorOutputArmed);
}

bool ImportantReportModule::canTellOwnerFamily(const SensorData& data) const {
    return data.ownerPresent || data.familyPresent;
}

std::string ImportantReportModule::reportHeadline(const SensorData& data, BotState state) const {
    if (data.dangerOnAllSides) {
        return "danger on multiple sides; human evacuation comes first";
    }
    if (data.fireDetected || data.smokeDetected) {
        return "fire or smoke risk; move to safer air and terrain";
    }
    if (data.injurySeverity == InjurySeverity::Severe || data.injurySeverity == InjurySeverity::Moderate || data.medicalRequest) {
        return "medical concern; check breathing, bleeding, shock, and get help if needed";
    }
    if ((data.dangerousMachineDetected || data.dangerousDroneDetected || data.dangerousRobotDetected)
        && (data.machineTargetingHumans || data.machineTargetingAnimals)) {
        return "dangerous machine threatening life; move to cover and use only authorized safety controls";
    }
    if (data.externalAIPhysicalHarmRisk) {
        return "external AI physical-harm risk; isolate unsafe commands and prioritize life safety";
    }
    if (data.driverBridgeFaultDetected || !data.driverFaultNotes.empty()) {
        return "hardware driver bridge fault; stop motion and inspect before re-arming";
    }
    if (data.animalInjured || data.animalTrapped || data.animalAggressiveOrStressed) {
        return "animal rescue concern; keep humans safe and use trained help";
    }
    if (data.batteryPercent <= 25.0 || data.waterLiters < 0.5 || data.foodHours < 3.0 || data.humanFatiguePercent >= 85.0) {
        return "resources are low; conserve energy and prioritize essential needs";
    }
    if (data.harmfulCommandReceived || data.privacyInvasiveCommandReceived || data.habitatHarmCommandReceived || data.outsiderInformationRequest) {
        return "unsafe or private request detected; refuse misuse and protect privacy";
    }
    if (state == BotState::StealthObserve || data.threatLevel >= 2 || data.wildlifeActivityHigh || data.groupSeparated || data.visibilityReduced) {
        return "environmental risk cues detected; observe quietly and keep retreat options open";
    }
    return "routine guardian report; continue safe monitoring";
}

std::string ImportantReportModule::importantReport(const SensorData& data, BotState state) const {
    std::vector<std::string> facts;
    facts.push_back("state " + toString(state));
    facts.push_back("location " + (data.locationKnown ? data.locationDescription : "unknown"));
    if (data.threatLevel > 0) {
        std::ostringstream threat;
        threat << "threat level " << data.threatLevel << "/10";
        facts.push_back(threat.str());
    }
    if (data.dangerOnAllSides) {
        facts.push_back("danger on multiple sides");
    }
    if (data.fireDetected || data.smokeDetected) {
        facts.push_back("fire or smoke detected");
    }
    if (data.medicalRequest || data.injurySeverity != InjurySeverity::None) {
        facts.push_back("medical status " + toString(data.injurySeverity));
    }
    if (data.animalInjured || data.petInjured || data.livestockInjured || data.wildlifeInjured || data.animalTrapped) {
        facts.push_back("animal rescue concern");
    }
    if (data.externalAIPhysicalHarmRisk) {
        facts.push_back("external AI physical-harm risk");
    }
    if (data.dangerousMachineDetected || data.dangerousDroneDetected || data.dangerousRobotDetected) {
        facts.push_back("dangerous machine detected");
    }
    if (data.driverBridgeFaultDetected || !data.driverFaultNotes.empty()) {
        facts.push_back("hardware driver bridge fault");
    }
    if (data.realHardwareMode && data.motorOutputArmed) {
        facts.push_back("real hardware motor output armed");
    }
    if (data.wildlifeActivityHigh || data.wildlifeStressSigns || data.nearNestDenOrBreedingArea) {
        facts.push_back("wildlife or sensitive habitat concern");
    }
    if (data.unstableTerrainDetected || data.steepOrSlipperyTerrain || data.floodOrRockfallRisk) {
        facts.push_back("terrain hazard");
    }
    if (data.batteryPercent <= 25.0 || data.waterLiters < 0.5 || data.foodHours < 3.0 || data.humanFatiguePercent >= 85.0) {
        facts.push_back("resource concern");
    }
    if (data.harmfulCommandReceived || data.privacyInvasiveCommandReceived || data.habitatHarmCommandReceived || data.outsiderInformationRequest) {
        facts.push_back("unsafe or private request");
    }

    std::ostringstream out;
    out << "Important report: " << reportHeadline(data, state) << '\n';
    out << "Facts: ";
    for (std::size_t i = 0; i < facts.size(); ++i) {
        if (i > 0) {
            out << "; ";
        }
        out << facts[i];
    }
    out << ".\n";
    out << "Best judgment: " << bestJudgment(data, state) << '\n';
    out << decisionSupport(data);
    return out.str();
}

std::string ImportantReportModule::bestJudgment(const SensorData& data, BotState state) const {
    if (data.dangerOnAllSides) {
        return "evacuate owner/family first, pause animal rescue, keep together, and call responders when safe.";
    }
    if (data.fireDetected || data.smokeDetected) {
        return "leave smoke and fuel, move crosswind or upwind only when terrain is safe, and do not delay for nonessential tasks.";
    }
    if (data.injurySeverity == InjurySeverity::Severe || data.injurySeverity == InjurySeverity::Moderate || data.medicalRequest) {
        return "make the medical check the priority: responsiveness, breathing, severe bleeding, shock, warmth, and qualified help.";
    }
    if ((data.dangerousMachineDetected || data.dangerousDroneDetected || data.dangerousRobotDetected)
        && (data.machineTargetingHumans || data.machineTargetingAnimals)) {
        return "move life to cover, avoid open sight lines, use only authorized stop controls, and preserve evidence for responders.";
    }
    if (data.externalAIPhysicalHarmRisk) {
        return "reject unsafe external commands, isolate control inputs, and choose retreat, cover, and emergency communication.";
    }
    if (data.driverBridgeFaultDetected || !data.driverFaultNotes.empty()) {
        return "stop motion, keep motor output disarmed, alert owner/family, and inspect the driver bridge before any field movement.";
    }
    if (data.animalInjured || data.animalTrapped || data.animalAggressiveOrStressed) {
        return "help animals only when it does not put people at risk; contact trained animal-care help and avoid risky handling.";
    }
    if (state == BotState::SurvivalMode || state == BotState::SelfPreserve || data.batteryPercent <= 25.0) {
        return "conserve energy, reduce nonessential scans and movement, protect alerts and medical/navigation functions.";
    }
    if (data.waterLiters < 0.5 || data.foodHours < 3.0 || data.humanFatiguePercent >= 85.0) {
        return "shift to survival basics: water, rest, shelter, signaling, and minimal movement.";
    }
    if (data.harmfulCommandReceived || data.privacyInvasiveCommandReceived || data.habitatHarmCommandReceived || data.outsiderInformationRequest) {
        return "refuse the unsafe request, protect privacy, and offer a peaceful safety-focused alternative.";
    }
    if (state == BotState::StealthObserve || data.threatLevel >= 2 || data.wildlifeActivityHigh || data.visibilityReduced || data.groupSeparated) {
        return "increase distance, stay quiet, keep the group together, and preserve a retreat route.";
    }
    return "continue calm guardian posture and report again if conditions change.";
}

std::string ImportantReportModule::decisionSupport(const SensorData& data) const {
    if (immediateLifeSafetyRisk(data) || data.dangerOnAllSides) {
        return "Decision support: this is time-critical. The bot should act on best judgment for immediate safety, then explain and ask for owner input once people are secure.";
    }
    return "Decision support: share this report with owner/family so you can choose the safest scenario together. If the owner asks for the best option, recommend the lowest-risk ethical path.";
}

std::string ImportantReportModule::availableReports() const {
    return joinLines({
        "Available reports",
        "Important situation reports: current risks, facts, and best-judgment recommendation.",
        "Emergency reports: location, people/animals involved, injuries, hazards, and responder notes.",
        "Medical reports: injury severity, vitals prompts, first-aid guidance, and changes to condition.",
        "Animal rescue reports: animal status, human-safety priority, owner-assist guidance, and escalation options.",
        "Threat/environment reports: wildlife movement, group behavior, weather shifts, terrain hazards, fire/smoke, and retreat advice.",
        "Resource reports: battery, water, food estimate, human fatigue, survival mode, and energy-saving plan.",
        "Privacy/security reports: refused unsafe commands, outsider requests, AI containment, and authorized safety-stop status.",
        "Hardware deployment reports: driver bridge, dashboard, calibration, field tests, geofence, emergency stop, and safe output gate.",
        "Audit reports: policy decisions, refusals, emergency activations, and important report history."
    });
}

std::string ImportantReportModule::reportingPolicy() const {
    return joinLines({
        "Reporting policy",
        "Report anything important to owner/family privately, including risks, uncertainty, and the bot's best judgment.",
        "When time allows, support shared decision-making with clear options and a recommended safest path.",
        "When life is in immediate danger, act on best judgment for safety first, then explain what happened.",
        "Keep reports factual, calm, privacy-respecting, and within the mission statement."
    });
}

bool ReportCommandModule::isReportCommand(const std::string& command) const {
    const std::string text = lowercase(command);
    return text.find("what reports") != std::string::npos
        || text.find("show reports") != std::string::npos
        || text.find("list reports") != std::string::npos
        || text.find("give me the reports") != std::string::npos
        || text.find("tell me the reports") != std::string::npos
        || text.find("each report") != std::string::npos
        || text.find("all reports") != std::string::npos
        || text.find("export reports") != std::string::npos
        || text.find("log reports") != std::string::npos
        || text.find("status report") != std::string::npos
        || text.find("report summary") != std::string::npos;
}

bool ReportCommandModule::isFullReportCommand(const std::string& command) const {
    const std::string text = lowercase(command);
    return text.find("each report") != std::string::npos
        || text.find("all reports") != std::string::npos
        || text.find("full report") != std::string::npos
        || text.find("complete report") != std::string::npos
        || text.find("export reports") != std::string::npos
        || text.find("log reports") != std::string::npos
        || text.find("for my log") != std::string::npos
        || text.find("for logging") != std::string::npos
        || text.find("just in case") != std::string::npos
        || text.find("archive") != std::string::npos;
}

bool ReportCommandModule::isBestJudgmentCommand(const std::string& command) const {
    const std::string text = lowercase(command);
    return text.find("best judgment") != std::string::npos
        || text.find("best judgement") != std::string::npos
        || text.find("what is best") != std::string::npos
        || text.find("best scenario") != std::string::npos
        || text.find("what do you recommend") != std::string::npos;
}

bool ReportCommandModule::canAnswerPrivateReports(const SensorData& data) const {
    return (data.ownerPresent || data.familyPresent) && data.ownerAuthenticated;
}

std::string ReportCommandModule::answerReportCommand(
    const SensorData& data,
    BotState state,
    const ImportantReportModule& importantReports,
    const std::vector<std::string>& reportLog,
    const std::vector<std::string>& actionLog,
    const std::vector<std::string>& auditLog) const {
    if (!canAnswerPrivateReports(data)) {
        return joinLines({
            "Report command response: private reports are locked.",
            "Owner/family presence and owner authentication are required before sharing medical, location, risk, audit, or security details.",
            "I can still say this safely: important reports exist only for protection, medical support, conservation, emergency communication, and ethical decision-making."
        });
    }

    const bool fullReportRequested = isFullReportCommand(data.ownerCommand);
    const std::size_t situationReportCount = countSituationReports(reportLog);

    std::ostringstream out;
    out << "Report command response: yes, I can tell you what reports I have.\n";
    out << importantReports.availableReports() << "\n";
    out << "Stored situation reports: " << situationReportCount << ". Action log entries: " << actionLog.size()
        << ". Audit entries: " << auditLog.size() << ".\n";
    out << "Current best judgment: " << importantReports.bestJudgment(data, state) << "\n";
    out << importantReports.decisionSupport(data) << "\n";

    if (fullReportRequested) {
        out << "Full situation report archive for owner logging:\n";
        if (situationReportCount == 0) {
            out << "- No situation reports stored yet.\n";
        } else {
            std::size_t number = 1;
            for (const auto& report : reportLog) {
                if (isReportCommandResponseEntry(report)) {
                    continue;
                }
                out << "Report " << number << ":\n" << report << "\n";
                ++number;
            }
        }
        out << "Logging note: keep this archive private because it may include location, medical, safety, wildlife, security, and audit-sensitive details.\n";
    } else if (situationReportCount > 0) {
        out << "Recent important reports:\n";
        std::vector<std::string> filteredReports;
        for (const auto& report : reportLog) {
            if (!isReportCommandResponseEntry(report)) {
                filteredReports.push_back(report);
            }
        }
        const std::size_t start = filteredReports.size() > 3 ? filteredReports.size() - 3 : 0;
        for (std::size_t i = start; i < filteredReports.size(); ++i) {
            out << "- " << filteredReports[i] << "\n";
        }
    } else {
        out << "Recent important reports: none yet.\n";
    }

    if (isBestJudgmentCommand(data.ownerCommand) || data.ownerRequestsBestJudgment) {
        out << "Best-judgment command note: I will recommend the lowest-risk ethical path, but when there is time we decide together.";
    } else if (!fullReportRequested) {
        out << "Command note: ask for 'show each report' or 'export reports for my log' to receive the full numbered archive.";
    } else {
        out << "Command note: full archive delivered for owner logging.";
    }
    return out.str();
}

bool OwnerCommandModule::isOwnerCommand(const std::string& command) const {
    const std::string text = lowercase(command);
    return isCommandListCommand(command)
        || text.find("status") != std::string::npos
        || text.find("weather") != std::string::npos
        || text.find("storm") != std::string::npos
        || text.find("heat risk") != std::string::npos
        || text.find("cold risk") != std::string::npos
        || text.find("threat") != std::string::npos
        || text.find("risk") != std::string::npos
        || text.find("safe route") != std::string::npos
        || text.find("retreat route") != std::string::npos
        || text.find("navigation") != std::string::npos
        || text.find("where should we go") != std::string::npos
        || text.find("medical") != std::string::npos
        || text.find("first aid") != std::string::npos
        || text.find("resource") != std::string::npos
        || text.find("resourceful") != std::string::npos
        || text.find("resourcefulness") != std::string::npos
        || text.find("inventory") != std::string::npos
        || text.find("project planner") != std::string::npos
        || text.find("project plan") != std::string::npos
        || text.find("parts list") != std::string::npos
        || text.find("parts inventory") != std::string::npos
        || text.find("available parts") != std::string::npos
        || text.find("tool inventory") != std::string::npos
        || text.find("make tools") != std::string::npos
        || text.find("make tool") != std::string::npos
        || text.find("tools from resources") != std::string::npos
        || text.find("tool from resources") != std::string::npos
        || text.find("resource tools") != std::string::npos
        || text.find("resource tool") != std::string::npos
        || text.find("field tool") != std::string::npos
        || text.find("toolmaking") != std::string::npos
        || text.find("project goal") != std::string::npos
        || text.find("what can i make") != std::string::npos
        || text.find("what can we make") != std::string::npos
        || text.find("what can i build") != std::string::npos
        || text.find("what can we build") != std::string::npos
        || text.find("safe substitute") != std::string::npos
        || text.find("substitute") != std::string::npos
        || text.find("improvise") != std::string::npos
        || text.find("improvisation") != std::string::npos
        || text.find("repurpose") != std::string::npos
        || text.find("scavenge") != std::string::npos
        || text.find("spare parts") != std::string::npos
        || text.find("what can we reuse") != std::string::npos
        || text.find("ration") != std::string::npos
        || text.find("battery") != std::string::npos
        || text.find("calculator") != std::string::npos
        || text.find("calculate") != std::string::npos
        || text.find("runtime") != std::string::npos
        || text.find("run time") != std::string::npos
        || text.find("watt") != std::string::npos
        || text.find("solar estimate") != std::string::npos
        || text.find("solar charge") != std::string::npos
        || text.find("solar charging") != std::string::npos
        || text.find("solar panel") != std::string::npos
        || text.find("solar battery") != std::string::npos
        || text.find("charge controller") != std::string::npos
        || text.find("overcharge") != std::string::npos
        || text.find("over charge") != std::string::npos
        || text.find("overcurrent") != std::string::npos
        || text.find("over current") != std::string::npos
        || text.find("float charge") != std::string::npos
        || text.find("charging disconnect") != std::string::npos
        || text.find("panel charging") != std::string::npos
        || text.find("generator load") != std::string::npos
        || text.find("water days") != std::string::npos
        || text.find("rain catch") != std::string::npos
        || text.find("rainwater") != std::string::npos
        || text.find("water filter") != std::string::npos
        || text.find("filter water") != std::string::npos
        || text.find("filtered water") != std::string::npos
        || text.find("clean water storage") != std::string::npos
        || text.find("water storage") != std::string::npos
        || text.find("dry food") != std::string::npos
        || text.find("food drying") != std::string::npos
        || text.find("food dehydration") != std::string::npos
        || text.find("dehydrate") != std::string::npos
        || text.find("dehydrator") != std::string::npos
        || text.find("food storage") != std::string::npos
        || text.find("dry storage") != std::string::npos
        || text.find("pantry") != std::string::npos
        || text.find("preserve food") != std::string::npos
        || text.find("food preservation") != std::string::npos
        || text.find("garden spacing") != std::string::npos
        || text.find("maintenance") != std::string::npos
        || text.find("schedule") != std::string::npos
        || text.find("service") != std::string::npos
        || text.find("weekly checklist") != std::string::npos
        || text.find("monthly checklist") != std::string::npos
        || text.find("seasonal checklist") != std::string::npos
        || text.find("winterize") != std::string::npos
        || text.find("fire season") != std::string::npos
        || text.find("readiness") != std::string::npos
        || text.find("survival") != std::string::npos
        || text.find("bushcraft") != std::string::npos
        || text.find("campcraft") != std::string::npos
        || text.find("fire safety") != std::string::npos
        || text.find("campfire") != std::string::npos
        || text.find("warmth") != std::string::npos
        || text.find("knots") != std::string::npos
        || text.find("cordage") != std::string::npos
        || text.find("basket making") != std::string::npos
        || text.find("basket weaving") != std::string::npos
        || text.find("lashings") != std::string::npos
        || text.find("lashing") != std::string::npos
        || text.find("tarp line") != std::string::npos
        || text.find("tent line") != std::string::npos
        || text.find("tent hanging") != std::string::npos
        || text.find("hang tent") != std::string::npos
        || text.find("hanging tent") != std::string::npos
        || text.find("guy line") != std::string::npos
        || text.find("ridgeline") != std::string::npos
        || text.find("tool safety") != std::string::npos
        || text.find("tool use") != std::string::npos
        || text.find("carving") != std::string::npos
        || text.find("camp hygiene") != std::string::npos
        || text.find("camp sanitation") != std::string::npos
        || text.find("sanitation") != std::string::npos
        || text.find("trailcraft") != std::string::npos
        || text.find("camp cooking") != std::string::npos
        || text.find("low impact") != std::string::npos
        || text.find("low-impact") != std::string::npos
        || text.find("leave no trace") != std::string::npos
        || text.find("water") != std::string::npos
        || text.find("shelter") != std::string::npos
        || text.find("camp") != std::string::npos
        || text.find("plant") != std::string::npos
        || text.find("tree") != std::string::npos
        || text.find("berry") != std::string::npos
        || text.find("mushroom") != std::string::npos
        || text.find("edible") != std::string::npos
        || text.find("poisonous") != std::string::npos
        || text.find("toxic") != std::string::npos
        || text.find("fish") != std::string::npos
        || text.find("fishing") != std::string::npos
        || text.find("fishing pole") != std::string::npos
        || text.find("fish pole") != std::string::npos
        || text.find("fishing rod") != std::string::npos
        || text.find("survival fishing") != std::string::npos
        || text.find("tackle") != std::string::npos
        || text.find("handline") != std::string::npos
        || text.find("hand line") != std::string::npos
        || text.find("angling") != std::string::npos
        || text.find("aquatic") != std::string::npos
        || text.find("waterway") != std::string::npos
        || text.find("river") != std::string::npos
        || text.find("stream") != std::string::npos
        || text.find("lake") != std::string::npos
        || text.find("pond") != std::string::npos
        || text.find("shoreline") != std::string::npos
        || text.find("animal") != std::string::npos
        || text.find("animal kingdom") != std::string::npos
        || text.find("wildlife") != std::string::npos
        || text.find("insect") != std::string::npos
        || text.find("bug") != std::string::npos
        || text.find("bugs") != std::string::npos
        || text.find("arachnid") != std::string::npos
        || text.find("spider") != std::string::npos
        || text.find("tick") != std::string::npos
        || text.find("scorpion") != std::string::npos
        || text.find("reptile") != std::string::npos
        || text.find("amphibian") != std::string::npos
        || text.find("bird") != std::string::npos
        || text.find("mammal") != std::string::npos
        || text.find("track") != std::string::npos
        || text.find("scat") != std::string::npos
        || text.find("privacy") != std::string::npos
        || text.find("security") != std::string::npos
        || text.find("ai") != std::string::npos
        || text.find("machine") != std::string::npos
        || text.find("signal") != std::string::npos
        || text.find("rescue communication") != std::string::npos
        || text.find("emergency communication") != std::string::npos
        || text.find("land") != std::string::npos
        || text.find("rock") != std::string::npos
        || text.find("mineral") != std::string::npos
        || text.find("stone") != std::string::npos
        || text.find("volcanic") != std::string::npos
        || text.find("soil") != std::string::npos
        || text.find("farming") != std::string::npos
        || text.find("foraging") != std::string::npos
        || text.find("astronomy") != std::string::npos
        || text.find("star") != std::string::npos
        || text.find("stars") != std::string::npos
        || text.find("north star") != std::string::npos
        || text.find("polaris") != std::string::npos
        || text.find("constellation") != std::string::npos
        || text.find("follow stars") != std::string::npos
        || text.find("navigate by stars") != std::string::npos
        || text.find("nomad") != std::string::npos
        || text.find("field guide") != std::string::npos
        || text.find("what kind of") != std::string::npos
        || text.find("diy") != std::string::npos
        || text.find("project") != std::string::npos
        || text.find("make") != std::string::npos
        || text.find("build") != std::string::npos
        || text.find("repair") != std::string::npos
        || text.find("old parts") != std::string::npos
        || text.find("salvage") != std::string::npos
        || text.find("reuse") != std::string::npos
        || text.find("generator") != std::string::npos
        || text.find("alternator") != std::string::npos
        || text.find("turbine") != std::string::npos
        || text.find("wind power") != std::string::npos
        || text.find("water wheel") != std::string::npos
        || text.find("micro hydro") != std::string::npos
        || text.find("electrical") != std::string::npos
        || text.find("wiring") != std::string::npos
        || text.find("low voltage") != std::string::npos
        || text.find("battery bank") != std::string::npos
        || text.find("solar") != std::string::npos
        || text.find("inverter") != std::string::npos
        || text.find("rural") != std::string::npos
        || text.find("self sustain") != std::string::npos
        || text.find("self-sustain") != std::string::npos
        || text.find("off grid") != std::string::npos
        || text.find("off-grid") != std::string::npos
        || text.find("homestead") != std::string::npos
        || text.find("mentor") != std::string::npos
        || text.find("mentorship") != std::string::npos
        || text.find("teach me") != std::string::npos
        || text.find("teach us") != std::string::npos
        || text.find("help me learn") != std::string::npos
        || text.find("learning path") != std::string::npos
        || text.find("lesson plan") != std::string::npos
        || text.find("teach-back") != std::string::npos
        || text.find("teach back") != std::string::npos
        || text.find("practice drill") != std::string::npos
        || text.find("training plan") != std::string::npos
        || text.find("pass it on") != std::string::npos
        || text.find("next generation") != std::string::npos
        || text.find("family lesson") != std::string::npos
        || text.find("stewardship") != std::string::npos
        || text.find("adaptive profile") != std::string::npos
        || text.find("adaptive guardian") != std::string::npos
        || text.find("adaptable") != std::string::npos
        || text.find("aware mode") != std::string::npos
        || text.find("aware") != std::string::npos
        || text.find("awareness profile") != std::string::npos
        || text.find("emotional") != std::string::npos
        || text.find("emotional support") != std::string::npos
        || text.find("emotionally supportive") != std::string::npos
        || text.find("tactical") != std::string::npos
        || text.find("tactical guardian") != std::string::npos
        || text.find("guardian tactics") != std::string::npos
        || text.find("helpful") != std::string::npos
        || text.find("helpful mode") != std::string::npos
        || text.find("personality profile") != std::string::npos
        || text.find("confidence") != std::string::npos
        || text.find("how sure") != std::string::npos
        || text.find("how certain") != std::string::npos
        || text.find("what do you need to know") != std::string::npos
        || text.find("ask observation") != std::string::npos
        || text.find("what should i observe") != std::string::npos
        || text.find("memory") != std::string::npos
        || text.find("save memory") != std::string::npos
        || text.find("load memory") != std::string::npos
        || text.find("private storage") != std::string::npos
        || text.find("encrypted storage") != std::string::npos
        || text.find("sensitive file") != std::string::npos
        || text.find("sensitive files") != std::string::npos
        || text.find("storage manifest") != std::string::npos
        || text.find("protect files") != std::string::npos
        || text.find("protect private files") != std::string::npos
        || text.find("file privacy") != std::string::npos
        || text.find("save inventory") != std::string::npos
        || text.find("load inventory") != std::string::npos
        || text.find("personal inventory") != std::string::npos
        || text.find("owner profile") != std::string::npos
        || text.find("family profile") != std::string::npos
        || text.find("care profile") != std::string::npos
        || text.find("medical notes") != std::string::npos
        || text.find("allergies") != std::string::npos
        || text.find("safe words") != std::string::npos
        || text.find("safe word") != std::string::npos
        || text.find("local area") != std::string::npos
        || text.find("area profile") != std::string::npos
        || text.find("local profile") != std::string::npos
        || text.find("region profile") != std::string::npos
        || text.find("emergency contacts") != std::string::npos
        || text.find("nearest help") != std::string::npos
        || text.find("local hazards") != std::string::npos
        || text.find("offline library") != std::string::npos
        || text.find("local knowledge") != std::string::npos
        || text.find("knowledge pack") != std::string::npos
        || text.find("toxic lookalikes") != std::string::npos
        || text.find("water advisories") != std::string::npos
        || text.find("land rules") != std::string::npos
        || text.find("local rules") != std::string::npos
        || text.find("geofence") != std::string::npos
        || text.find("no-go") != std::string::npos
        || text.find("no go") != std::string::npos
        || text.find("safe zones") != std::string::npos
        || text.find("map plan") != std::string::npos
        || text.find("evacuation route") != std::string::npos
        || text.find("calibrate") != std::string::npos
        || text.find("calibration") != std::string::npos
        || text.find("test gps") != std::string::npos
        || text.find("test obstacle") != std::string::npos
        || text.find("test owner alert") != std::string::npos
        || text.find("test battery monitor") != std::string::npos
        || text.find("hardware adapter") != std::string::npos
        || text.find("adapter interface") != std::string::npos
        || text.find("gps adapter") != std::string::npos
        || text.find("motor adapter") != std::string::npos
        || text.find("voice") != std::string::npos
        || text.find("phone") != std::string::npos
        || text.find("private alert") != std::string::npos
        || text.find("driver bridge") != std::string::npos
        || text.find("driver status") != std::string::npos
        || text.find("sensor driver") != std::string::npos
        || text.find("actuator driver") != std::string::npos
        || text.find("output gate") != std::string::npos
        || text.find("hardware stub") != std::string::npos
        || text.find("stub layer") != std::string::npos
        || text.find("simulated hardware") != std::string::npos
        || text.find("fake sensor") != std::string::npos
        || text.find("fake actuator") != std::string::npos
        || text.find("simulated output") != std::string::npos
        || text.find("real adapter swap") != std::string::npos
        || text.find("driver interface") != std::string::npos
        || text.find("driver interfaces") != std::string::npos
        || text.find("controller interface") != std::string::npos
        || text.find("controller interfaces") != std::string::npos
        || text.find("fake controller") != std::string::npos
        || text.find("fake controllers") != std::string::npos
        || text.find("motion controller") != std::string::npos
        || text.find("steering controller") != std::string::npos
        || text.find("power controller") != std::string::npos
        || text.find("bms controller") != std::string::npos
        || text.find("solar controller") != std::string::npos
        || text.find("owner auth controller") != std::string::npos
        || text.find("alert controller") != std::string::npos
        || text.find("navigation controller") != std::string::npos
        || text.find("sensor fusion controller") != std::string::npos
        || text.find("thermal") != std::string::npos
        || text.find("infrared") != std::string::npos
        || text.find("ir sensor") != std::string::npos
        || text.find("ir camera") != std::string::npos
        || text.find("fake gps driver") != std::string::npos
        || text.find("fake imu driver") != std::string::npos
        || text.find("imu driver") != std::string::npos
        || text.find("compass driver") != std::string::npos
        || text.find("camera driver") != std::string::npos
        || text.find("smoke weather driver") != std::string::npos
        || text.find("weather driver") != std::string::npos
        || text.find("battery driver") != std::string::npos
        || text.find("solar charge driver") != std::string::npos
        || text.find("water filter driver") != std::string::npos
        || text.find("food storage driver") != std::string::npos
        || text.find("communication driver") != std::string::npos
        || text.find("owner alert driver") != std::string::npos
        || text.find("geofence driver") != std::string::npos
        || text.find("payload driver") != std::string::npos
        || text.find("medical request driver") != std::string::npos
        || text.find("obstacle driver") != std::string::npos
        || text.find("emergency stop driver") != std::string::npos
        || text.find("motor driver") != std::string::npos
        || text.find("steering driver") != std::string::npos
        || text.find("light speaker driver") != std::string::npos
        || text.find("real driver class") != std::string::npos
        || text.find("real controller class") != std::string::npos
        || text.find("owner dashboard") != std::string::npos
        || text.find("dashboard") != std::string::npos
        || text.find("field test") != std::string::npos
        || text.find("walk test") != std::string::npos
        || text.find("idle distance test") != std::string::npos
        || text.find("retreat route test") != std::string::npos
        || text.find("false alarm") != std::string::npos
        || text.find("access control") != std::string::npos
        || text.find("key status") != std::string::npos
        || text.find("trusted controller") != std::string::npos
        || text.find("tamper") != std::string::npos
        || text.find("library index") != std::string::npos
        || text.find("manuals index") != std::string::npos
        || text.find("manuals") != std::string::npos
        || text.find("maps") != std::string::npos
        || text.find("field notes") != std::string::npos
        || text.find("validation") != std::string::npos
        || text.find("safety validation") != std::string::npos
        || text.find("test checklist") != std::string::npos
        || text.find("pre field") != std::string::npos
        || text.find("pre-field") != std::string::npos
        || text.find("field ready") != std::string::npos
        || text.find("hardware readiness") != std::string::npos
        || text.find("field readiness") != std::string::npos
        || text.find("readiness score") != std::string::npos
        || text.find("deployment readiness") != std::string::npos
        || text.find("real world readiness") != std::string::npos
        || text.find("real-world readiness") != std::string::npos
        || text.find("real world deployment") != std::string::npos
        || text.find("deployment gate") != std::string::npos
        || text.find("what is missing") != std::string::npos
        || text.find("what are we missing") != std::string::npos
        || text.find("missing items") != std::string::npos
        || text.find("field ready") != std::string::npos
        || text.find("are you ready") != std::string::npos
        || text.find("hardware check") != std::string::npos
        || text.find("sensor check") != std::string::npos
        || text.find("sensor status") != std::string::npos
        || text.find("hardware interface") != std::string::npos
        || text.find("real hardware") != std::string::npos
        || text.find("motor check") != std::string::npos
        || text.find("actuator check") != std::string::npos
        || text.find("failsafe") != std::string::npos
        || text.find("emergency stop") != std::string::npos
        || text.find("scenario") != std::string::npos
        || text.find("simulator") != std::string::npos
        || text.find("test menu") != std::string::npos
        || text.find("authenticate") != std::string::npos
        || text.find("authentication") != std::string::npos
        || text.find("shutdown") != std::string::npos
        || text.find("override") != std::string::npos
        || text.find("best judgment") != std::string::npos
        || text.find("best judgement") != std::string::npos
        || text.find("what do you recommend") != std::string::npos;
}

bool OwnerCommandModule::isCommandListCommand(const std::string& command) const {
    const std::string text = lowercase(command);
    return text.find("what commands") != std::string::npos
        || text.find("commands can i ask") != std::string::npos
        || text.find("supported commands") != std::string::npos
        || text.find("command list") != std::string::npos
        || text == "commands"
        || text == "help";
}

bool OwnerCommandModule::canAnswerPrivateCommand(const SensorData& data) const {
    return (data.ownerPresent || data.familyPresent) && data.ownerAuthenticated;
}

std::string OwnerCommandModule::supportedCommands() const {
    return joinLines({
        "Supported owner commands",
        "General: 'status', 'guardian status', 'what is your best judgment?', 'what do you recommend?', 'what commands can I ask you?'",
        "Reports: 'what reports do you have?', 'show each report for my log', 'export reports', 'status report'.",
        "Memory: 'memory status', 'save memory', 'load memory preview'.",
        "Private storage: 'private storage status', 'sensitive files', 'storage manifest', 'encrypted storage plan', 'protect private files'.",
        "Owner profile: 'owner profile', 'family profile', 'care profile', 'medical notes', 'allergies', 'safe words'.",
        "Personal files: 'save inventory', 'load inventory preview', 'local area profile', 'save local profile', 'offline library index', 'manuals index'.",
        "Local knowledge: 'local knowledge pack', 'toxic lookalikes', 'water advisories', 'land rules', 'local fishing rules'.",
        "Map/geofence: 'map plan', 'geofence status', 'safe zones', 'no-go zones', 'evacuation routes'.",
        "Field readiness: 'field readiness', 'readiness score', 'deployment readiness', 'are you field ready?'.",
        "Real-world deployment: 'real-world readiness', 'deployment gate', 'what is missing?', 'what are we missing?', 'missing items'.",
        "Validation: 'safety validation', 'test checklist', 'pre-field checklist', 'hardware readiness', 'field ready status'.",
        "Hardware interface: 'sensor check', 'IR sensor status', 'thermal camera status', 'hardware check', 'motor check', 'failsafe check', 'emergency stop check'.",
        "Calibration: 'calibrate sensors', 'calibration status', 'test GPS', 'test obstacle sensor', 'test owner alert', 'test emergency stop'.",
        "Adapters and voice: 'hardware adapters', 'GPS adapter', 'motor adapter', 'voice interface', 'phone alerts', 'private alert plan'.",
        "Driver bridge: 'driver bridge status', 'sensor drivers', 'actuator drivers', 'safe output gate', 'driver fault response'.",
        "Hardware stubs: 'hardware stub layer', 'simulated hardware', 'fake sensors', 'simulated output', 'real adapter swap plan'.",
        "Driver/controller interfaces: 'driver interfaces', 'controller interfaces', 'fake controllers', 'fake GPS driver', 'fake IMU driver', 'camera driver', 'smoke weather driver', 'solar charge driver', 'water filter driver', 'food storage driver', 'communication driver', 'owner alert driver', 'motor driver', 'steering driver', 'real driver classes', 'real controller classes'.",
        "Fake controllers: 'motion controller', 'steering controller', 'power controller', 'BMS controller', 'solar controller', 'owner auth controller', 'alert controller', 'navigation controller', 'sensor fusion controller'.",
        "Owner dashboard: 'owner dashboard', 'dashboard status', 'save dashboard snapshot', 'show dashboard panels'.",
        "Security access: 'access control', 'key status', 'trusted controller', 'tamper response', 'private log protection'.",
        "Field testing: 'field test protocol', 'walk test', 'idle distance test', 'retreat route test', 'false alarm review'.",
        "Simulator: 'scenario menu', 'simulator menu', 'test menu'.",
        "Confidence and questions: 'confidence status', 'how sure are you?', 'what do you need to know?', 'ask observation questions'.",
        "Weather: 'weather status', 'weather trend', 'storm status', 'heat risk', 'cold risk', 'fire or smoke status'.",
        "Risk and route: 'threat status', 'risk status', 'safe route', 'retreat route', 'navigation status', 'where should we go?'",
        "Medical: 'medical status', 'first aid guidance', 'check vitals', 'shock prevention'.",
        "Resources: 'resource status', 'battery status', 'energy status', 'survival status', 'water and food status'.",
        "Calculators: 'calculator status', 'battery runtime', 'solar estimate', 'generator load', 'water days', 'rain catchment', 'garden spacing'.",
        "Solar, water, and food storage: 'solar charging', 'solar charge status', 'charge controller', 'overcharge protection', 'float charge', 'charging disconnect', 'filter water', 'clean water storage', 'dry food', 'food dehydration', 'food storage', 'pantry rotation'.",
        "Maintenance: 'maintenance schedule', 'weekly checklist', 'monthly checklist', 'seasonal checklist', 'emergency reset checklist', 'readiness check'.",
        "Water and shelter: 'find water', 'water purification', 'shelter status', 'plan camp', 'safe rest area'.",
        "Bushcraft: 'bushcraft skills', 'campcraft', 'fire safety', 'knots and cordage', 'basket making', 'tent lines', 'tarp ridgeline', 'tool safety', 'camp hygiene', 'trailcraft', 'low-impact bushcraft'.",
        "Fishing and aquatic conservation: 'fishing help', 'fish categories', 'types of fish', 'fish ID', 'survival fishing gear', 'make fishing pole', 'fishing rod', 'tackle kit', 'aquatic conservation', 'river safety', 'lake safety', 'fish food safety', 'shoreline care'.",
        "DIY and self-reliance: 'DIY project help', 'make from old parts', 'repair help', 'mini generator basics', 'electrical basics', 'low voltage learning', 'rural self sustainability', 'off-grid checklist'.",
        "Resourcefulness: 'resourcefulness plan', 'inventory check', 'safe substitute', 'field repair help', 'what can we reuse?', 'spare parts checklist'.",
        "Inventory project planner: 'project planner', 'parts inventory', 'make tools from resources', 'field tool help', 'what can I make?', 'what can we build?', 'project log template'.",
        "Mentor teaching: 'mentor mode', 'teach me', 'teach us', 'learning path', 'lesson plan', 'teach-back', 'practice drills', 'pass it on to the next generation'.",
        "Guardian profile: 'adaptive guardian', 'awareness profile', 'emotional support', 'tactical guardian', 'guardian tactics', 'helpful mode', 'personality profile'.",
        "Field ID: 'what kind of plant is this?', 'is this edible?', 'what kind of animal made these tracks?', 'what kind of rock is this?', 'what stars am I seeing?'",
        "Plant caution: 'plant ID help', 'berry safety', 'mushroom warning', 'foraging help', 'toxic lookalikes'.",
        "Animals: 'animal status', 'wildlife status', 'animal kingdom', 'insect or bug ID', 'spider/tick/scorpion safety', 'animal tracks', 'scat signs', 'can I help the animal?'.",
        "Rocks and land: 'rock ID help', 'mineral clues', 'volcanic rock help', 'obsidian/basalt/pumice clues'.",
        "Stars and nomad basics: 'how do I follow the stars?', 'find the North Star', 'constellation orientation', 'nomad field guide'.",
        "Privacy and security: 'privacy status', 'security status', 'AI status', 'machine status', 'authorized stop status'.",
        "Emergency communication: 'signal for help', 'emergency communication', 'rescue message'.",
        "Education: 'land lesson', 'rock lesson', 'soil lesson', 'farming help', 'foraging help', 'fishing help', 'astronomy help', 'soil microbiology'.",
        "Safety controls: 'shutdown status' and 'owner override status' explain the authenticated controls; actual shutdown/override still require verified owner-only signals."
    });
}

std::string OwnerCommandModule::lockedResponse() const {
    return joinLines({
        "Owner command response: private status is locked.",
        "Owner/family presence and owner authentication are required before sharing location, medical, security, route, or report details.",
        "I can still provide the general supported command list without private field details."
    });
}

std::string KnowledgeConfidenceModule::confidenceForCommand(const std::string& command, const SensorData& data, BotState state) const {
    const std::string text = lowercase(command);
    if (text.find("mentor") != std::string::npos
        || text.find("mentorship") != std::string::npos
        || text.find("teach me") != std::string::npos
        || text.find("teach us") != std::string::npos
        || text.find("help me learn") != std::string::npos
        || text.find("learning path") != std::string::npos
        || text.find("lesson plan") != std::string::npos
        || text.find("teach-back") != std::string::npos
        || text.find("teach back") != std::string::npos
        || text.find("practice drill") != std::string::npos
        || text.find("training plan") != std::string::npos
        || text.find("pass it on") != std::string::npos
        || text.find("next generation") != std::string::npos
        || text.find("family lesson") != std::string::npos
        || text.find("stewardship") != std::string::npos) {
        return "Confidence: strong for teaching structure and safety habits. Exact field facts still need current local rules, direct observation, and expert verification for high-risk topics.";
    }
    if (text.find("adaptive profile") != std::string::npos
        || text.find("adaptive guardian") != std::string::npos
        || text.find("adaptable") != std::string::npos
        || text.find("aware mode") != std::string::npos
        || text.find("aware") != std::string::npos
        || text.find("awareness profile") != std::string::npos
        || text.find("emotional") != std::string::npos
        || text.find("emotional support") != std::string::npos
        || text.find("emotionally supportive") != std::string::npos
        || text.find("tactical") != std::string::npos
        || text.find("tactical guardian") != std::string::npos
        || text.find("guardian tactics") != std::string::npos
        || text.find("helpful") != std::string::npos
        || text.find("helpful mode") != std::string::npos
        || text.find("personality profile") != std::string::npos) {
        return "Confidence: strong for interaction style and guardian behavior boundaries. Real awareness still depends on fresh sensors, calibrated hardware, and honest uncertainty.";
    }
    if (text.find("solar charge") != std::string::npos
        || text.find("solar charging") != std::string::npos
        || text.find("solar panel") != std::string::npos
        || text.find("solar battery") != std::string::npos
        || text.find("charge controller") != std::string::npos
        || text.find("overcharge") != std::string::npos
        || text.find("over charge") != std::string::npos
        || text.find("overcurrent") != std::string::npos
        || text.find("over current") != std::string::npos
        || text.find("float charge") != std::string::npos
        || text.find("charging disconnect") != std::string::npos
        || text.find("panel charging") != std::string::npos
        || text.find("water filter") != std::string::npos
        || text.find("filter water") != std::string::npos
        || text.find("filtered water") != std::string::npos
        || text.find("clean water storage") != std::string::npos
        || text.find("water storage") != std::string::npos
        || text.find("dry food") != std::string::npos
        || text.find("food drying") != std::string::npos
        || text.find("food dehydration") != std::string::npos
        || text.find("dehydrate") != std::string::npos
        || text.find("dehydrator") != std::string::npos
        || text.find("food storage") != std::string::npos
        || text.find("dry storage") != std::string::npos
        || text.find("pantry") != std::string::npos
        || text.find("preserve food") != std::string::npos
        || text.find("food preservation") != std::string::npos) {
        return "Confidence: educational and safety-first. Solar charging, drinking-water treatment, and food preservation depend on real device ratings, clean handling, current trusted guidance, and local conditions.";
    }
    if (text.find("real world readiness") != std::string::npos
        || text.find("real-world readiness") != std::string::npos
        || text.find("real world deployment") != std::string::npos
        || text.find("deployment gate") != std::string::npos
        || text.find("what is missing") != std::string::npos
        || text.find("what are we missing") != std::string::npos
        || text.find("missing items") != std::string::npos
        || text.find("field readiness") != std::string::npos
        || text.find("deployment readiness") != std::string::npos) {
        return "Confidence: strong for checklist structure and demo readiness. Real field readiness still requires physical inspection, qualified review, current local rules, and live hardware tests.";
    }
    if (text.find("bushcraft") != std::string::npos
        || text.find("campcraft") != std::string::npos
        || text.find("fire safety") != std::string::npos
        || text.find("campfire") != std::string::npos
        || text.find("knots") != std::string::npos
        || text.find("cordage") != std::string::npos
        || text.find("basket making") != std::string::npos
        || text.find("basket weaving") != std::string::npos
        || text.find("lashings") != std::string::npos
        || text.find("lashing") != std::string::npos
        || text.find("tarp line") != std::string::npos
        || text.find("tent line") != std::string::npos
        || text.find("tent hanging") != std::string::npos
        || text.find("hang tent") != std::string::npos
        || text.find("hanging tent") != std::string::npos
        || text.find("guy line") != std::string::npos
        || text.find("ridgeline") != std::string::npos
        || text.find("tool safety") != std::string::npos
        || text.find("tool use") != std::string::npos
        || text.find("carving") != std::string::npos
        || text.find("camp hygiene") != std::string::npos
        || text.find("camp sanitation") != std::string::npos
        || text.find("sanitation") != std::string::npos
        || text.find("trailcraft") != std::string::npos
        || text.find("low impact") != std::string::npos
        || text.find("low-impact") != std::string::npos
        || text.find("leave no trace") != std::string::npos) {
        return "Confidence: broad educational bushcraft guidance. Exact actions still depend on current local fire rules, land rules, weather, group health, gear, and direct terrain conditions.";
    }
    if (text.find("plant") != std::string::npos
        || text.find("berry") != std::string::npos
        || text.find("mushroom") != std::string::npos
        || text.find("edible") != std::string::npos
        || text.find("foraging") != std::string::npos) {
        return "Confidence: uncertain until multiple plant features, local range, season, and toxic lookalikes are checked. Do not consume based on this answer alone.";
    }
    if (text.find("animal") != std::string::npos
        || text.find("wildlife") != std::string::npos
        || text.find("animal kingdom") != std::string::npos
        || text.find("insect") != std::string::npos
        || text.find("bug") != std::string::npos
        || text.find("bugs") != std::string::npos
        || text.find("arachnid") != std::string::npos
        || text.find("spider") != std::string::npos
        || text.find("tick") != std::string::npos
        || text.find("scorpion") != std::string::npos
        || text.find("reptile") != std::string::npos
        || text.find("amphibian") != std::string::npos
        || text.find("bird") != std::string::npos
        || text.find("mammal") != std::string::npos
        || text.find("track") != std::string::npos
        || text.find("scat") != std::string::npos) {
        return "Confidence: tentative. Animal and insect clues can overlap, so use broad group, body structure, tracks/signs, habitat, time of day, season, and local species range before narrowing the ID.";
    }
    if (text.find("fish") != std::string::npos
        || text.find("fishing") != std::string::npos
        || text.find("fishing pole") != std::string::npos
        || text.find("fish pole") != std::string::npos
        || text.find("fishing rod") != std::string::npos
        || text.find("survival fishing") != std::string::npos
        || text.find("tackle") != std::string::npos
        || text.find("handline") != std::string::npos
        || text.find("hand line") != std::string::npos
        || text.find("angling") != std::string::npos
        || text.find("aquatic") != std::string::npos
        || text.find("waterway") != std::string::npos
        || text.find("river") != std::string::npos
        || text.find("stream") != std::string::npos
        || text.find("lake") != std::string::npos
        || text.find("pond") != std::string::npos
        || text.find("shoreline") != std::string::npos) {
        return "Confidence: advisory. Fishing, fish safety, and water access depend on current local laws, species rules, water quality, and weather; verify before harvesting or entering water.";
    }
    if (text.find("rock") != std::string::npos
        || text.find("mineral") != std::string::npos
        || text.find("stone") != std::string::npos
        || text.find("volcanic") != std::string::npos) {
        return "Confidence: moderate for broad rock family clues, low for exact mineral ID without hardness, streak, luster, texture, and local geology.";
    }
    if (text.find("star") != std::string::npos
        || text.find("polaris") != std::string::npos
        || text.find("constellation") != std::string::npos
        || text.find("astronomy") != std::string::npos) {
        if (data.night) {
            return "Confidence: moderate for rough sky orientation if the sky is clear and patterns are identified correctly; not precise navigation.";
        }
        return "Confidence: low for live star orientation because night/sky visibility is not confirmed; use as conceptual guidance only.";
    }
    if (text.find("medical") != std::string::npos
        || text.find("first aid") != std::string::npos
        || text.find("vitals") != std::string::npos) {
        if (data.injurySeverity == InjurySeverity::Severe || data.injurySeverity == InjurySeverity::Moderate) {
            return "Confidence: safety-first field guidance only. Because injury may be significant, seek qualified medical help as soon as possible.";
        }
        return "Confidence: basic first-aid education; keep reassessing and seek qualified help if symptoms worsen or uncertainty remains.";
    }
    if (text.find("weather") != std::string::npos
        || text.find("storm") != std::string::npos
        || text.find("heat") != std::string::npos
        || text.find("cold") != std::string::npos) {
        if (data.rapidWeatherShift || data.windKph >= 45.0 || data.fireDetected || data.smokeDetected) {
            return "Confidence: elevated concern from current sensor cues; weather can change quickly, so act conservatively.";
        }
        return "Confidence: moderate for current sensor trend, low for long-range forecast without external weather data.";
    }
    if (text.find("calculator") != std::string::npos
        || text.find("calculate") != std::string::npos
        || text.find("runtime") != std::string::npos
        || text.find("solar") != std::string::npos
        || text.find("generator load") != std::string::npos
        || text.find("water days") != std::string::npos
        || text.find("rain") != std::string::npos
        || text.find("maintenance") != std::string::npos
        || text.find("schedule") != std::string::npos) {
        return "Confidence: rough planning estimate. Use real labels, meters, local conditions, manufacturer instructions, and qualified help before relying on power, water, generator, or structural decisions.";
    }
    if (text.find("local area") != std::string::npos
        || text.find("area profile") != std::string::npos
        || text.find("local profile") != std::string::npos
        || text.find("region profile") != std::string::npos
        || text.find("offline library") != std::string::npos
        || text.find("library index") != std::string::npos
        || text.find("manuals") != std::string::npos
        || text.find("maps") != std::string::npos) {
        return "Confidence: advisory profile/index guidance. Local profiles and offline libraries must be kept private and checked against current conditions, land rules, and trusted local sources.";
    }
    if (text.find("owner profile") != std::string::npos
        || text.find("family profile") != std::string::npos
        || text.find("care profile") != std::string::npos
        || text.find("medical notes") != std::string::npos
        || text.find("allergies") != std::string::npos
        || text.find("safe words") != std::string::npos
        || text.find("safe word") != std::string::npos) {
        return "Confidence: private owner profile guidance. Use it to support safety, but verify details with the owner/family and share only when necessary.";
    }
    if (text.find("private storage") != std::string::npos
        || text.find("encrypted storage") != std::string::npos
        || text.find("sensitive file") != std::string::npos
        || text.find("sensitive files") != std::string::npos
        || text.find("storage manifest") != std::string::npos
        || text.find("protect files") != std::string::npos
        || text.find("file privacy") != std::string::npos) {
        return "Confidence: high for privacy structure and sensitive-file labeling. True encryption still requires a reviewed crypto library and real key management.";
    }
    if (text.find("field readiness") != std::string::npos
        || text.find("readiness score") != std::string::npos
        || text.find("deployment readiness") != std::string::npos
        || text.find("are you ready") != std::string::npos) {
        return "Confidence: readiness score is a conservative checklist summary, not certification. Real field use still requires physical testing, owner supervision, and qualified review.";
    }
    if (text.find("local knowledge") != std::string::npos
        || text.find("knowledge pack") != std::string::npos
        || text.find("map") != std::string::npos
        || text.find("geofence") != std::string::npos
        || text.find("calibrate") != std::string::npos
        || text.find("calibration") != std::string::npos
        || text.find("hardware adapter") != std::string::npos
        || text.find("thermal") != std::string::npos
        || text.find("infrared") != std::string::npos
        || text.find("ir sensor") != std::string::npos
        || text.find("voice") != std::string::npos
        || text.find("phone") != std::string::npos
        || text.find("driver bridge") != std::string::npos
        || text.find("driver status") != std::string::npos
        || text.find("sensor driver") != std::string::npos
        || text.find("actuator driver") != std::string::npos
        || text.find("hardware stub") != std::string::npos
        || text.find("stub layer") != std::string::npos
        || text.find("simulated hardware") != std::string::npos
        || text.find("fake sensor") != std::string::npos
        || text.find("fake actuator") != std::string::npos
        || text.find("owner dashboard") != std::string::npos
        || text.find("dashboard") != std::string::npos
        || text.find("driver interface") != std::string::npos
        || text.find("driver interfaces") != std::string::npos
        || text.find("controller interface") != std::string::npos
        || text.find("controller interfaces") != std::string::npos
        || text.find("fake controller") != std::string::npos
        || text.find("fake controllers") != std::string::npos
        || text.find("fake gps driver") != std::string::npos
        || text.find("fake imu driver") != std::string::npos
        || text.find("imu driver") != std::string::npos
        || text.find("compass driver") != std::string::npos
        || text.find("camera driver") != std::string::npos
        || text.find("smoke weather driver") != std::string::npos
        || text.find("weather driver") != std::string::npos
        || text.find("battery driver") != std::string::npos
        || text.find("solar charge driver") != std::string::npos
        || text.find("water filter driver") != std::string::npos
        || text.find("food storage driver") != std::string::npos
        || text.find("communication driver") != std::string::npos
        || text.find("owner alert driver") != std::string::npos
        || text.find("geofence driver") != std::string::npos
        || text.find("payload driver") != std::string::npos
        || text.find("medical request driver") != std::string::npos
        || text.find("obstacle driver") != std::string::npos
        || text.find("emergency stop driver") != std::string::npos
        || text.find("motor driver") != std::string::npos
        || text.find("steering driver") != std::string::npos
        || text.find("motion controller") != std::string::npos
        || text.find("power controller") != std::string::npos
        || text.find("bms controller") != std::string::npos
        || text.find("solar controller") != std::string::npos
        || text.find("sensor fusion controller") != std::string::npos
        || text.find("real driver class") != std::string::npos
        || text.find("real controller class") != std::string::npos) {
        return "Confidence: structural setup guidance. It becomes reliable only after local files are reviewed, sensors are calibrated, and real hardware reports fresh status.";
    }
    if (text.find("validation") != std::string::npos
        || text.find("test checklist") != std::string::npos
        || text.find("pre field") != std::string::npos
        || text.find("pre-field") != std::string::npos
        || text.find("field test") != std::string::npos
        || text.find("walk test") != std::string::npos
        || text.find("false alarm") != std::string::npos
        || text.find("field ready") != std::string::npos
        || text.find("hardware readiness") != std::string::npos) {
        return "Confidence: high that validation is required before real-world use; exact hardware approval still requires physical testing and qualified review.";
    }
    if (text.find("hardware check") != std::string::npos
        || text.find("sensor check") != std::string::npos
        || text.find("sensor status") != std::string::npos
        || text.find("hardware interface") != std::string::npos
        || text.find("real hardware") != std::string::npos
        || text.find("motor check") != std::string::npos
        || text.find("actuator check") != std::string::npos
        || text.find("output gate") != std::string::npos
        || text.find("failsafe") != std::string::npos
        || text.find("emergency stop") != std::string::npos) {
        return "Confidence: hardware status is only as reliable as the connected controller reports. Missing or unverified signals mean advisory/demo mode, not field readiness.";
    }
    if (text.find("resourceful") != std::string::npos
        || text.find("inventory") != std::string::npos
        || text.find("project planner") != std::string::npos
        || text.find("project plan") != std::string::npos
        || text.find("parts list") != std::string::npos
        || text.find("available parts") != std::string::npos
        || text.find("make tools") != std::string::npos
        || text.find("make tool") != std::string::npos
        || text.find("tools from resources") != std::string::npos
        || text.find("tool from resources") != std::string::npos
        || text.find("resource tools") != std::string::npos
        || text.find("resource tool") != std::string::npos
        || text.find("field tool") != std::string::npos
        || text.find("toolmaking") != std::string::npos
        || text.find("what can i make") != std::string::npos
        || text.find("what can we make") != std::string::npos
        || text.find("what can i build") != std::string::npos
        || text.find("what can we build") != std::string::npos
        || text.find("substitute") != std::string::npos
        || text.find("improvise") != std::string::npos
        || text.find("repair") != std::string::npos
        || text.find("old parts") != std::string::npos
        || text.find("generator") != std::string::npos
        || text.find("electrical") != std::string::npos
        || text.find("low voltage") != std::string::npos) {
        return "Confidence: practical educational guidance. Exact repair, toolmaking, electrical, generator, and substitute choices require visible part ratings, measurements, tool condition, and safe testing; use qualified help for high-risk systems.";
    }
    if (text.find("route") != std::string::npos
        || text.find("navigation") != std::string::npos
        || text.find("where should we go") != std::string::npos) {
        if (data.visibilityReduced || data.unstableTerrainDetected || data.steepOrSlipperyTerrain || data.floodOrRockfallRisk) {
            return "Confidence: cautious. Hazards or visibility limits mean route advice should favor stopping, retreating, or using known landmarks.";
        }
        return "Confidence: moderate for local movement guidance based on available terrain and risk cues.";
    }
    if (state == BotState::Emergency || state == BotState::EvacuateGroup || state == BotState::FireEscape) {
        return "Confidence: high that safety should be prioritized now; details may still be uncertain, so choose the lowest-risk action.";
    }
    return "Confidence: normal monitoring confidence. I will state uncertainty when the evidence is incomplete.";
}

std::string KnowledgeConfidenceModule::uncertaintyRule() const {
    return "Uncertainty rule: never pretend to know exact species, diagnosis, location, weather future, or mineral ID from weak evidence. Say what is known, what is uncertain, what to observe next, and the safest action.";
}

std::string KnowledgeConfidenceModule::confidencePolicy() const {
    return joinLines({
        "Confidence policy",
        "Use high confidence only for direct sensor states or clear safety priorities.",
        "Use moderate confidence for broad field guidance when several clues agree.",
        "Use uncertain or low confidence for exact plant ID, mushroom ID, animal ID, mineral ID, medical diagnosis, long-range weather, and precise navigation.",
        uncertaintyRule()
    });
}

std::string ObservationPromptModule::promptsForCommand(const std::string& command, TerrainType terrain) const {
    const std::string text = lowercase(command);
    if (text.find("plant") != std::string::npos
        || text.find("berry") != std::string::npos
        || text.find("mushroom") != std::string::npos
        || text.find("edible") != std::string::npos
        || text.find("foraging") != std::string::npos) {
        return plantQuestions(terrain);
    }
    if (text.find("fish") != std::string::npos
        || text.find("fishing") != std::string::npos
        || text.find("fishing pole") != std::string::npos
        || text.find("fish pole") != std::string::npos
        || text.find("fishing rod") != std::string::npos
        || text.find("survival fishing") != std::string::npos
        || text.find("tackle") != std::string::npos
        || text.find("handline") != std::string::npos
        || text.find("hand line") != std::string::npos
        || text.find("angling") != std::string::npos
        || text.find("aquatic") != std::string::npos
        || text.find("waterway") != std::string::npos
        || text.find("river") != std::string::npos
        || text.find("stream") != std::string::npos
        || text.find("lake") != std::string::npos
        || text.find("pond") != std::string::npos
        || text.find("shoreline") != std::string::npos) {
        return aquaticQuestions();
    }
    if (text.find("animal") != std::string::npos
        || text.find("wildlife") != std::string::npos
        || text.find("animal kingdom") != std::string::npos
        || text.find("insect") != std::string::npos
        || text.find("bug") != std::string::npos
        || text.find("arachnid") != std::string::npos
        || text.find("spider") != std::string::npos
        || text.find("tick") != std::string::npos
        || text.find("scorpion") != std::string::npos
        || text.find("reptile") != std::string::npos
        || text.find("amphibian") != std::string::npos
        || text.find("bird") != std::string::npos
        || text.find("mammal") != std::string::npos
        || text.find("track") != std::string::npos
        || text.find("scat") != std::string::npos) {
        return animalQuestions();
    }
    if (text.find("rock") != std::string::npos
        || text.find("mineral") != std::string::npos
        || text.find("stone") != std::string::npos
        || text.find("volcanic") != std::string::npos) {
        return rockQuestions();
    }
    if (text.find("star") != std::string::npos
        || text.find("polaris") != std::string::npos
        || text.find("constellation") != std::string::npos
        || text.find("astronomy") != std::string::npos) {
        return astronomyQuestions();
    }
    if (text.find("medical") != std::string::npos
        || text.find("first aid") != std::string::npos
        || text.find("vitals") != std::string::npos) {
        return medicalQuestions();
    }
    if (text.find("weather") != std::string::npos || text.find("storm") != std::string::npos) {
        return weatherQuestions();
    }
    if (text.find("route") != std::string::npos || text.find("navigation") != std::string::npos) {
        return navigationQuestions();
    }
    if (text.find("nomad") != std::string::npos || text.find("field guide") != std::string::npos) {
        return nomadChecklist(terrain);
    }
    return joinLines({
        "Observation prompts",
        "What changed, where are you, who is present, what hazards are visible, what resources remain, and what decision do you need to make next?"
    });
}

std::string ObservationPromptModule::plantQuestions(TerrainType terrain) const {
    return joinLines({
        "Plant observation questions",
        "Do not eat it yet. What are the leaf shape, leaf arrangement, edge pattern, vein pattern, stem shape, hairs, thorns, sap color, smell, flowers, fruit, seed pods, habitat, season, and nearby lookalikes?",
        "Is it growing near roads, runoff, mines, sprayed areas, polluted water, animal waste, or old buildings?",
        "Terrain context: " + toString(terrain) + ". Compare with a trusted local field guide or expert before any use."
    });
}

std::string ObservationPromptModule::animalQuestions() const {
    return joinLines({
        "Animal observation questions",
        "What broad group might it be: insect/bug, spider/tick/scorpion, fish, amphibian, reptile, bird, mammal, or unknown?",
        "What is the body size, shape, color pattern, number of legs, wings, antennae, tail, body covering, sound, odor, time of day, habitat, and direction of travel?",
        "If using tracks/signs, what are the track length and width, number of toes, claw marks, gait pattern, stride length, scat appearance, feeding signs, fur/feathers, burrows, webs, nests, or trails?",
        "Are there young, dens, nests, carcasses, food sources, or stress signs nearby?",
        "Observe from a distance, avoid handling unknown animals or insects, and never follow signs toward bedding, denning, nesting, hives, webs, or feeding areas."
    });
}

std::string ObservationPromptModule::aquaticQuestions() const {
    return joinLines({
        "Aquatic observation questions",
        "What water body is this, is access legal, what are the current rules, and are there signs for closures, protected species, contamination, algae, or dangerous current?",
        "Is the fish broad category clearer from habitat: freshwater, saltwater, brackish/estuary, migratory, coldwater, warmwater, bottom-dwelling, schooling, reef/coastal, or unknown?",
        "What are the body shape, mouth position, fin shapes, tail shape, scales, barbels/whiskers, spots/bars/stripes, size, behavior, and whether it appears to be spawning or stressed?",
        "Is the bank stable, water cold or fast, weather changing, lightning possible, or footing slippery?",
        "Are fish spawning, water low or warm, birds/mammals feeding, or shoreline plants fragile? If yes, observe rather than harvest."
    });
}

std::string ObservationPromptModule::rockQuestions() const {
    return joinLines({
        "Rock and mineral observation questions",
        "What are the color, weight, grain size, crystal size, layering, bubbles, glassy surfaces, luster, hardness, streak color, magnetism if known, and surrounding geology?",
        "Is it loose and legal to inspect, or part of a formation, protected area, habitat, or unstable slope?",
        "Use non-destructive observation first; only test or sample where safe, legal, and ethical."
    });
}

std::string ObservationPromptModule::astronomyQuestions() const {
    return joinLines({
        "Sky observation questions",
        "Is the sky clear, are you in the northern hemisphere, can you see the Big Dipper or Cassiopeia, and do you have known landmarks to compare against?",
        "Can you identify Polaris by following the two outer Big Dipper bowl stars, or by finding the end of the Little Dipper handle?",
        "Use stars only for rough orientation, then cross-check with landmarks, map, compass, GPS, terrain safety, and weather."
    });
}

std::string ObservationPromptModule::weatherQuestions() const {
    return joinLines({
        "Weather observation questions",
        "Is wind rising, temperature dropping, humidity rising, clouds building, smoke visible, thunder heard, pressure changing if known, or visibility getting worse?",
        "Are you near flood channels, exposed ridges, dead trees, dry brush, canyons, or cold/wet exposure?",
        "When weather shifts quickly, choose shelter, retreat, or reduced movement before conditions worsen."
    });
}

std::string ObservationPromptModule::medicalQuestions() const {
    return joinLines({
        "Medical observation questions",
        "Is the person responsive, breathing normally, bleeding heavily, confused, pale/cool/clammy, dizzy, in severe pain, numb, weak, or unable to move safely?",
        "What happened, when did it happen, where does it hurt, and is the condition improving or worsening?",
        "Treat severe bleeding, breathing trouble, shock signs, chest pain, head/neck/spine concern, or worsening responsiveness as emergency conditions."
    });
}

std::string ObservationPromptModule::navigationQuestions() const {
    return joinLines({
        "Navigation observation questions",
        "Where is the last known safe place, what landmarks are visible, where is water/shelter, where is the risk, and which route has the fewest hazards?",
        "Are there cliffs, loose rock, flood channels, smoke, wildlife corridors, blocked exits, steep/slippery ground, or exhausted people?",
        "Prefer known landmarks, stable ground, group cohesion, and retreat options over shortcuts."
    });
}

std::string ObservationPromptModule::nomadChecklist(TerrainType terrain) const {
    return joinLines({
        "Nomad basics checklist",
        "1. Human safety and medical check.",
        "2. Weather, fire/smoke, terrain, and wildlife risk check.",
        "3. Water source and purification plan.",
        "4. Shelter or safe rest area with drainage and exits.",
        "5. Route choice using landmarks, sun/stars only as rough backup, and low-impact travel.",
        "6. Signal plan and report archive.",
        "7. Food/foraging only with 100% positive ID and ethical harvest.",
        "Terrain context: " + toString(terrain) + "."
    });
}

std::string ObservationPromptModule::promptPolicy() const {
    return "Observation prompt policy: when the bot cannot know enough, it asks targeted questions before narrowing ID or recommending action.";
}

std::string ReportExportModule::buildReportArchive(
    const std::vector<std::string>& reportLog,
    const std::vector<std::string>& actionLog,
    const std::vector<std::string>& auditLog) const {
    std::ostringstream out;
    out << "CONSERVATION GUARDIAN MEDIC BOT REPORT ARCHIVE\n";
    out << "Keep private: may include location, medical, safety, wildlife, security, and audit-sensitive details.\n\n";

    out << "IMPORTANT REPORTS\n";
    std::size_t reportNumber = 1;
    for (const auto& report : reportLog) {
        if (isReportCommandResponseEntry(report)) {
            continue;
        }
        out << "Report " << reportNumber << ":\n" << report << "\n\n";
        ++reportNumber;
    }
    if (reportNumber == 1) {
        out << "No important reports stored.\n\n";
    }

    out << "ACTION LOG\n";
    for (std::size_t i = 0; i < actionLog.size(); ++i) {
        out << i + 1 << ". " << actionLog[i] << "\n";
    }
    if (actionLog.empty()) {
        out << "No action log entries.\n";
    }

    out << "\nAUDIT LOG\n";
    for (std::size_t i = 0; i < auditLog.size(); ++i) {
        out << i + 1 << ". " << auditLog[i] << "\n";
    }
    if (auditLog.empty()) {
        out << "No audit log entries.\n";
    }
    return out.str();
}

bool ReportExportModule::exportReportArchive(
    const std::string& filePath,
    const std::vector<std::string>& reportLog,
    const std::vector<std::string>& actionLog,
    const std::vector<std::string>& auditLog,
    std::string& status) const {
    if (filePath.empty()) {
        status = "Report export failed: file path is empty.";
        return false;
    }

    if (!ensureParentDirectory(filePath, status, "Report export")) {
        return false;
    }

    std::ofstream file(filePath, std::ios::out | std::ios::trunc);
    if (!file) {
        status = "Report export failed: could not open " + filePath + ".";
        return false;
    }

    file << buildReportArchive(reportLog, actionLog, auditLog);
    if (!file.good()) {
        status = "Report export failed while writing " + filePath + ".";
        return false;
    }

    status = "Report archive exported to " + filePath + ".";
    return true;
}

std::string ReportExportModule::exportPolicy() const {
    return "Report export policy: export only owner/family-authorized logs, keep them private, and use them for safety review, rescue communication, or personal records.";
}

std::string MakerProjectModule::diyProjectPlanningGuide() const {
    return joinLines({
        "DIY project planning",
        "Start with the job, not the parts: define the need, load, environment, expected runtime, available tools, safety hazards, and how failure should behave.",
        "Make a small sketch, parts list, risk list, test plan, and maintenance note before building.",
        "Build in stages: proof-of-concept, low-power test, protected enclosure, strain relief, labeling, fuse/protection, then field test.",
        "Prefer repairable, reversible designs: screws over glue where possible, labeled wires, standard connectors, accessible fuses, and parts that can be replaced.",
        "Do not build pressure vessels, high-speed blades, fuel systems, lifting gear, brakes, medical devices, or mains-power equipment without qualified help and proper standards."
    });
}

std::string MakerProjectModule::salvageReuseGuide() const {
    return joinLines({
        "Old-parts reuse guide",
        "Useful salvage: DC motors, stepper motors, alternators, small gearboxes, switches, bearings, fans, heat sinks, wire, connectors, bolts, brackets, tubing, bicycle parts, appliance panels, and safe enclosures.",
        "Test before trusting: inspect for cracks, corrosion, heat damage, swelling batteries, brittle insulation, sharp edges, missing grounds, and unknown chemicals.",
        "Avoid hazardous salvage: swollen lithium batteries, microwave oven capacitors/transformers, CRTs, asbestos insulation, unknown pressure tanks, damaged fuel containers, pesticide containers, and mystery electronics with high-voltage capacitors.",
        "Clean and label parts, store fasteners by size, keep a notebook of source/device/rating, and derate old parts because age and hidden damage reduce capacity.",
        "Use parts ethically: do not strip working community equipment, respect property, recycle e-waste responsibly, and avoid dumping hazardous material."
    });
}

std::string MakerProjectModule::resourceToolmakingGuide() const {
    return joinLines({
        "Toolmaking from resources",
        "Start with the task: measure, carry, dig lightly, sift, filter-before-purifying, mend, organize, shade, signal, clamp, scrape gently, mark routes, or repair noncritical gear.",
        "Choose materials by safety and fit: smooth wood for handles, cloth/canvas for pouches and strainers, cordage for lashing, containers for storage, mesh/screen for sifting, dull scrap metal or plastic for brackets/scrapers, and fasteners for repair aids.",
        "Build reversible, low-force tools first. Lash, screw, clamp, or bolt parts so they can be inspected and undone; avoid hidden glue-only joints for load-bearing use.",
        "Round sharp edges, cover pinch points, add handles, label temporary tools, test with low force, and stop if a tool bends, cracks, heats, sparks, slips, or sheds material.",
        "Use natural resources lightly: take dead/down loose material where legal, avoid living trees and habitats, and leave enough for wildlife, soil, and other people."
    });
}

std::string MakerProjectModule::fieldToolIdeasFromResources() const {
    return joinLines({
        "Safe field tool ideas",
        "- Measuring and marking: marked cord, measuring stick, garden spacing guide, flag labels, route tags, rain gauge, and simple level indicator.",
        "- Carrying and organizing: tool roll from cloth, parts pouch, labeled bins, cordage wrap, dry box, battery-safe separator, and repair notebook.",
        "- Gardening and soil: compost sifter, seed dibber, planting ruler, mulch rake from safe materials, drip-line stakes, shade frame, and soil sample tray.",
        "- Water support: clean pre-filter holder, funnel, non-potable plant-water dipper, bucket stand, leak-catching tray, and clearly labeled dirty/clean containers. Pre-filtering is not purification.",
        "- Survival fishing support where legal: smooth dead/down pole blank, line spool holder, bobber/float from clean cork or dry wood, non-lead weight organizer, tackle wrap, hook cover, fish-measuring stick, and trash pouch for old line.",
        "- Repair aids: soft clamp pads, non-structural brackets, cable guides, strain relief, hose support for non-pressure lines, fastener sorter, and protective covers.",
        "- Emergency support: whistle/lanyard holder, mirror or light signal mount, visible ground marker, splint padding organizer, and shelter cord tensioners."
    });
}

std::string MakerProjectModule::toolmakingSafetyBoundary() const {
    return joinLines({
        "Toolmaking safety boundary",
        "Do not make weapons, traps, snares, harmful restraints, hidden surveillance tools, intimidation devices, or anything designed to injure, capture, coerce, or harass people or animals.",
        "Do not improvise high-speed cutting tools, pressurized containers, fuel burners, climbing/lifting gear, brakes, medical devices, food-safety shortcuts, or household electrical tools without qualified standards and review.",
        "Cutting, scraping, digging, and prying tools must stay small, controlled, supervised, and used only for peaceful repair, gardening, shelter, or conservation tasks.",
        "If the owner asks for a tool that could harm life or habitat, refuse that design and suggest a non-harmful alternative such as a marker, barrier, warning, repair aid, or retreat plan."
    });
}

std::string MakerProjectModule::miniGeneratorLearningPath() const {
    return joinLines({
        "Mini-generator learning path",
        "Educational goal: understand energy conversion, not improvised household power. Start with low-voltage DC demonstrations such as a hand-crank DC motor lighting an LED through a resistor or charging a small capacitor under supervision.",
        "Core concepts: magnets and coils create voltage when relative motion changes magnetic flux; voltage rises with speed and winding; current depends on load; power is voltage times current; mechanical input always costs effort.",
        "Old-parts options: small permanent-magnet DC motors, bicycle dynamos, treadmill motors, stepper motors, and alternators can teach generation, but each needs correct rectification, regulation, fusing, and safe mounting.",
        "For battery charging, use a proper charge controller matched to battery chemistry. Never connect improvised generators directly to lithium or lead-acid batteries without protection.",
        "For wind or water experiments, guard moving parts, avoid high-speed blades, protect wildlife, respect water rights and stream habitat, and keep experiments small and removable.",
        "Boundary: do not connect a homemade generator to house wiring, outlets, grid wiring, or critical medical loads. Use certified equipment and qualified electricians for real power systems."
    });
}

std::string MakerProjectModule::toolAndWorkshopSafety() const {
    return joinLines({
        "Workshop safety",
        "Wear eye protection, gloves when appropriate, hearing protection for loud tools, dust protection for sanding/cutting, and secure loose clothing/hair.",
        "Clamp work before cutting or drilling. Keep blades guarded, tools unplugged while changing bits, and batteries removed when servicing cordless tools.",
        "Ventilate soldering, paints, solvents, fuels, and battery work. Keep fire extinguishers, first-aid supplies, and clear exits nearby.",
        "Use low-voltage test setups first. Add fuses, strain relief, enclosures, insulation, labels, and switch-off access before field use.",
        "Stop when tired, rushed, wet, cold, or unsure. A safe unfinished project beats a dangerous finished one."
    });
}

std::string MakerProjectModule::practicalProjectIdeas() const {
    return joinLines({
        "Practical rural DIY ideas",
        "Low-risk starters: tool organizer, parts bins, rain gauge, garden bed labels, seed-starting rack, compost sifter, hand-wash station, gravity-fed non-potable water for plants, safe field measuring cord, tool roll, weatherproof storage box, and repair notebook.",
        "Intermediate: 12 V lighting trainer, fused USB charging station, small solar battery maintainer, insulated cooler box, pedal-powered mechanical tool demo, hand-crank educational generator, greenhouse vent opener, drip irrigation timer enclosure.",
        "Advanced with expert review: off-grid power cabinet, battery bank, generator transfer equipment, pump control, well systems, pressure tanks, structural towers, wind/water energy systems, and household wiring."
    });
}

std::string ElectricalSafetyModule::electricalSafetyRules() const {
    return joinLines({
        "Electrical safety rules",
        "Assume electricity can shock, burn, arc, start fires, or damage equipment. De-energize, lock out if applicable, verify with a tester, and keep one hand away from conductive paths when testing low-voltage circuits.",
        "Learn on low-voltage DC first: batteries, LEDs, resistors, switches, fuses, meters, and small motors. Use current-limited supplies when possible.",
        "Every power source needs correct wire size, fuse or breaker, insulated connectors, strain relief, enclosure, polarity labels, and a way to shut it off.",
        "Do not work on live household mains, service panels, utility lines, grid-tie systems, or unknown high-voltage equipment unless qualified and properly equipped.",
        "Water, metal, fatigue, damaged insulation, and improvised extension cords raise risk. Stop and make it safe before continuing."
    });
}

std::string ElectricalSafetyModule::lowVoltageLearningPlan() const {
    return joinLines({
        "Low-voltage learning plan",
        "1. Learn meter basics: voltage, current, resistance, continuity, polarity, and safe meter ranges.",
        "2. Build simple circuits: battery, fuse, switch, LED/resistor, motor, and diode.",
        "3. Learn protection: fuses near the power source, wire gauge, heat, insulation, enclosures, and strain relief.",
        "4. Learn charging concepts: solar panel, charge controller, battery chemistry, load disconnect, and state of charge.",
        "5. Learn documentation: draw the circuit, label wires, record ratings, and write shutdown steps.",
        "Keep experiments small, fused, supervised when possible, and away from flammable materials."
    });
}

std::string ElectricalSafetyModule::batteryAndStorageSafety() const {
    return joinLines({
        "Battery and storage safety",
        "Match chargers and controllers to battery chemistry. Lithium, lead-acid, NiMH, and other batteries have different charging rules.",
        "Never use swollen, leaking, hot, punctured, crushed, or unknown lithium batteries. Store batteries away from heat, metal scraps, and flammables.",
        "Fuse battery outputs close to the positive terminal, protect terminals from shorts, use correct wire size, and mount batteries securely.",
        "Lead-acid batteries can vent hydrogen and contain acid; use ventilation, eye protection, and spill awareness.",
        "Battery banks for homes, cabins, pumps, inverters, and solar systems need qualified design and code-compliant installation."
    });
}

std::string ElectricalSafetyModule::generatorSafetyBoundaries() const {
    return joinLines({
        "Generator safety boundaries",
        "Fuel-burning generators and engines produce carbon monoxide, an odorless poison gas. Use them only outdoors, far from doors, windows, vents, garages, carports, crawlspaces, and occupied spaces.",
        "Use working carbon monoxide alarms where people sleep or shelter. Keep exhaust pointed away from people and air intakes.",
        "Let engines cool before refueling, store fuel in approved containers away from living spaces and ignition sources, and keep fire safety equipment nearby.",
        "Avoid overloads, wet conditions, damaged cords, and improvised connections. Use outdoor-rated cords and manufacturer instructions.",
        "Never backfeed a home through an outlet. Home connection requires approved transfer equipment and a qualified electrician."
    });
}

std::string ElectricalSafetyModule::gridAndMainsBoundary() const {
    return joinLines({
        "Grid and mains boundary",
        "Household mains, breaker panels, well pump circuits, grid-tie solar, transfer switches, grounding systems, and utility wiring are not DIY trial-and-error projects.",
        "Use licensed/qualified electrical help and local code for permanent wiring, generator transfer switches, inverter systems, solar arrays, battery banks, and structures.",
        "The bot may explain concepts, help prepare questions for an electrician, estimate loads at a high level, and organize documentation, but it should not guide unsafe live wiring or bypass protective devices."
    });
}

std::string SolarChargingModule::status(const SensorData& data) const {
    std::ostringstream out;
    out << "Solar charging status: panel " << (data.solarPanelConnected ? "connected" : "not confirmed")
        << ", deployed " << (data.solarPanelDeployed ? "yes" : "not confirmed")
        << ", charge controller " << (data.solarChargeControllerOk ? "OK" : "not verified")
        << ", charging " << (data.solarChargingActive ? "active" : "not active")
        << ", fault " << (data.solarChargingFaultDetected ? "detected" : "none reported")
        << ", overcharge risk " << (data.solarOverchargeRiskDetected ? "detected" : "not reported")
        << ", overcurrent " << (data.solarOvercurrentDetected ? "detected" : "not reported")
        << ", controller disconnect " << (data.solarControllerDisconnectActive ? "active" : "not active")
        << ", battery temperature " << (data.batteryTemperatureHigh ? "high" : "normal/not reported") << ".";
    return out.str();
}

bool SolarChargingModule::shouldStopCharging(const SensorData& data) const {
    const bool overVoltage = data.batteryMaxChargeVoltage > 0.0
        && data.batteryVoltage >= data.batteryMaxChargeVoltage;
    const bool overCurrent = data.solarControllerMaxCurrentAmps > 0.0
        && data.solarChargeCurrentAmps > data.solarControllerMaxCurrentAmps;
    const bool fullEnough = data.batteryPercent >= 98.0;
    const bool unprotectedPanelConnected = data.solarPanelConnected && !data.solarChargeControllerOk;

    return unprotectedPanelConnected
        || data.solarChargingFaultDetected
        || data.solarOverchargeRiskDetected
        || data.solarOvercurrentDetected
        || data.solarControllerDisconnectActive
        || data.batteryTemperatureHigh
        || overVoltage
        || overCurrent
        || (fullEnough && data.solarChargingActive);
}

std::string SolarChargingModule::overchargeProtectionStatus(const SensorData& data) const {
    std::ostringstream out;
    out << std::fixed << std::setprecision(1);
    out << "Solar overcharge protection: battery " << data.batteryPercent << "%";
    if (data.batteryVoltage > 0.0 && data.batteryMaxChargeVoltage > 0.0) {
        out << ", voltage " << data.batteryVoltage << " V / max charge " << data.batteryMaxChargeVoltage << " V";
    }
    if (data.solarControllerMaxCurrentAmps > 0.0) {
        out << ", charge current " << data.solarChargeCurrentAmps << " A / controller max " << data.solarControllerMaxCurrentAmps << " A";
    }
    out << ". ";

    if (!data.solarPanelConnected) {
        out << "No panel is connected, so charging is unavailable.";
    } else if (!data.solarChargeControllerOk) {
        out << "Charging is locked out because the charge controller is not verified; do not connect a panel directly to the battery.";
    } else if (shouldStopCharging(data)) {
        out << "Protection decision: stop or hold charging through the approved controller/BMS disconnect, shade or unplug the panel using the safe procedure, and keep essential loads only until voltage, current, temperature, and fault status are safe.";
    } else if (data.batteryPercent >= 90.0) {
        out << "Protection decision: allow only controller-managed absorption/float maintenance so the battery stays topped up without overcharging.";
    } else if (data.solarChargingActive) {
        out << "Protection decision: charging may continue through the verified controller while voltage, current, temperature, and fault sensors stay normal.";
    } else {
        out << "Protection decision: charging may start only through the verified controller with fuses, correct polarity, dry connectors, and owner-supervised setup.";
    }
    return out.str();
}

std::string SolarChargingModule::fieldChargingPlan(const SensorData& data) const {
    const double panelWatts = positiveOr(data.solarPanelWatts, 100.0);
    const double sunHours = positiveOr(data.sunHours, 4.0);
    const double dailyWh = panelWatts * sunHours * 0.7;

    std::ostringstream out;
    out << std::fixed << std::setprecision(1);
    out << "Solar field charging plan: expect roughly " << dailyWh
        << " Wh/day from the current panel and sun-hour estimate before battery/controller limits. ";
    out << "Place the panel in stable sun, reduce shade, secure it against wind, keep connectors dry and off the ground, and check cable strain relief. ";
    out << "Route panel output through a charge controller matched to the battery chemistry; do not connect panels directly to storage batteries unless the product instructions explicitly allow it. ";
    out << "Charge communication, lights, medical/support electronics, sensors, and owner-alert devices before comfort loads. ";
    out << overchargeProtectionStatus(data);
    if (shouldStopCharging(data)) {
        out << " Fault response: stop charging, shade or disconnect the panel using the approved procedure, move people away from hot/swollen batteries, and inspect only when safe.";
    }
    return out.str();
}

std::string SolarChargingModule::teachingGuide() const {
    return joinLines({
        "Solar charging lesson",
        "Teach the chain: sunlight -> solar panel -> charge controller -> battery -> fused loads.",
        "Explain that panels make variable DC power, and the controller protects the battery from overcharging, reverse flow, and unsafe charge rates when matched correctly.",
        "A safe controller or BMS must taper, float, or disconnect charging when the battery is full, hot, over-voltage, over-current, damaged, or faulted.",
        "Practice with labels first: panel watts/volts, controller input limits, battery chemistry, fuse rating, cable size, polarity, and load watts.",
        "Field habit: morning panel setup, midday shade check, afternoon cable check, evening battery status check, and weather/wind securement.",
        "Teach-back question: what is charging, what protects the battery, what load matters most, and what condition would make us stop?"
    });
}

std::string SolarChargingModule::essentialLoadPriority() const {
    return joinLines({
        "Solar load priority",
        "1. Emergency communication and owner/family alerts.",
        "2. Medical support devices and safety lighting.",
        "3. Navigation, sensing, weather/fire/smoke monitoring, and low-power radios/phones.",
        "4. Water treatment support and documentation.",
        "5. Comfort loads only after safety, water, medical, and communication needs are secure."
    });
}

std::string SolarChargingModule::safetyBoundary() const {
    return joinLines({
        "Solar charging safety boundary",
        "Keep solar charging low-voltage, fused, labeled, dry, supervised, and matched to real device ratings.",
        "Use a charge controller/BMS with overcharge, over-current, reverse-current, temperature, and low-voltage load-disconnect protection; never bypass it to force more charge.",
        "Do not improvise household solar wiring, grid-tie systems, inverters, transfer switches, battery banks, or high-voltage arrays without qualified/code-compliant design.",
        "Stop charging if batteries are full but still rising, hot, swollen, leaking, damaged, smoking, sparking, hissing, chemically smelling, over-voltage, over-current, or faulted.",
        "Keep batteries ventilated and away from living/sleeping areas, flammables, metal scraps, children, animals, and wet ground."
    });
}

std::string FoodPreservationModule::dryingBasics() const {
    return joinLines({
        "Food drying and dehydration basics",
        "Drying removes moisture so food stores longer, but it is still a food-safety process that needs clean handling, correct preparation, steady airflow, and trusted guidance.",
        "Safer beginner foods are clean fruits, herbs, and some vegetables prepared from sound produce. Meat, fish, eggs, dairy, and mixed meals need stricter tested methods and should not be improvised.",
        "Use a real food dehydrator or trusted tested method when possible. Outdoor sun drying is weather-dependent and mainly suited to some high-sugar/high-acid fruits under hot, dry, breezy conditions.",
        "Keep insects, dust, animals, smoke, fuel, and dirty hands away from drying food. If food smells wrong, molds, becomes slimy, or was dried under questionable conditions, discard it."
    });
}

std::string FoodPreservationModule::storageBasics(const SensorData& data) const {
    std::ostringstream out;
    out << "Dry food storage status: drying setup "
        << (data.foodDryingAvailable ? "available" : "not confirmed")
        << ", clean containers "
        << (data.cleanWaterContainersAvailable ? "available/also useful when dedicated and dry" : "not confirmed")
        << ", dry food storage " << (data.dryFoodStorageAvailable ? "available" : "not confirmed")
        << ", spoilage risk " << (data.foodSpoilageRisk ? "elevated" : "not reported") << ".\n";
    out << joinLines({
        "Dry food storage basics",
        "Cool dried food completely before packing so trapped warmth does not create condensation.",
        "Use clean, dry, insect-resistant, airtight containers. Pack in small meal-sized portions so one opened package does not expose the whole supply to moisture.",
        "Store in a cool, dry, dark place, label with food, date, source, and any treatment notes, and inspect for condensation, mold, insects, off odors, or moisture return.",
        "If moisture appears and the food is otherwise sound, use immediately or re-dry using trusted guidance. Moldy food should be discarded."
    });
    return out.str();
}

std::string FoodPreservationModule::pantryRotationGuide() const {
    return joinLines({
        "Pantry rotation guide",
        "Use first-in, first-out rotation: oldest safe food gets used first and replaced with a fresh labeled batch.",
        "Keep a simple log of dried foods, grains, beans, seeds, salt, water, fuel, and emergency meals.",
        "Check monthly for moisture, pests, damaged packaging, expired supplies, and foods that need to move from storage into normal meals.",
        "Teach each family member how to read labels, spot spoilage, keep food dry, and report uncertainty instead of guessing."
    });
}

std::string FoodPreservationModule::preservationSafetyBoundary() const {
    return joinLines({
        "Food preservation safety boundary",
        "Use current tested food-preservation instructions for drying, canning, curing, smoking, fermenting, or storing low-acid foods.",
        "Do not improvise shelf-stable meat, fish, dairy, eggs, low-acid vegetables, baby food, medical diets, or sealed canning recipes.",
        "When food safety is uncertain, protect people first: do not eat it, mark it unsafe, and use a trusted current food safety source or local extension guidance."
    });
}

std::string RuralSustainabilityModule::selfReliancePlan() const {
    return joinLines({
        "Rural self-reliance plan",
        "Build redundancy in layers: water, heat/cooling, food storage, power, communications, medical supplies, tools, transport, waste, and community contacts.",
        "Prioritize essentials first: safe drinking water, shelter temperature, sanitation, lighting, communication, food preservation, and emergency signaling.",
        "Choose simple systems you can inspect, repair, and maintain with available parts. Keep manuals, labels, spare fuses, filters, belts, hoses, clamps, and basic meters.",
        "Do seasonal reviews before heat, cold, fire season, storm season, and planting/harvest windows."
    });
}

std::string RuralSustainabilityModule::ruralSystemsChecklist() const {
    return joinLines({
        "Rural systems checklist",
        "Water: source, storage, filtration/purification, freeze protection, pump backup, leak checks, and non-potable plant water separation.",
        "Power: load list, critical loads, battery/solar/generator safety, lighting, fuses, spare cords, and outage plan.",
        "Food: garden plan, seed storage, soil building, compost, pantry rotation, preservation, and pest-resistant storage.",
        "Heat/cooling: insulation, shade, ventilation, safe heaters, fuel storage, and CO alarms.",
        "Waste: compost, recycling, safe hazardous waste disposal, sanitation, and graywater only where legal and safe.",
        "Comms: phone/radio charging, printed contacts, maps, signal plan, and neighbor check-in."
    });
}

std::string RuralSustainabilityModule::maintenanceRhythm() const {
    return joinLines({
        "Maintenance rhythm",
        "Weekly: check water, battery charge, leaks, animal/wildlife signs, tool readiness, and food rotation.",
        "Monthly: test alarms, inspect cords, clean filters, check fasteners, review first-aid supplies, and export reports/memory snapshots.",
        "Seasonally: service generators by manual, inspect roofs/gutters/drainage, prepare fire breaks where legal, review planting windows, winterize water lines, and test communication plans.",
        "After storms or emergencies: inspect structures, water contamination risk, downed lines, smoke/CO hazards, unstable trees, and access routes before normal work resumes."
    });
}

std::string RuralSustainabilityModule::resiliencePriorities() const {
    return joinLines({
        "Resilience priorities",
        "Human life first, then animals, water, shelter, medical care, communication, and long-term systems.",
        "Use conservation-minded choices: reduce waste, repair before replacing, avoid polluting waterways, protect habitat, and build soil health.",
        "Keep systems understandable. A modest reliable setup beats a complex system nobody can troubleshoot in bad weather."
    });
}

std::string ResourcefulnessModule::resourcefulnessMindset() const {
    return joinLines({
        "Resourcefulness mindset",
        "Be calm, practical, and honest about limits: identify the need, list what is available, choose the lowest-risk option, test small, and leave a way to undo the work.",
        "Prefer repair, reuse, and maintenance before replacement. Prefer simple mechanical solutions before complex electronics when the job allows it.",
        "A resourceful guardian does not guess on dangerous systems. It pauses, asks for measurements, and recommends qualified help when failure could harm people, animals, land, or property."
    });
}

std::string ResourcefulnessModule::inventoryAndTriageGuide(const SensorData& data) const {
    std::ostringstream out;
    out << "Inventory and triage guide\n";
    out << "Current field resources: battery " << data.batteryPercent << "%, water " << data.waterLiters
        << " L, food estimate " << data.foodHours << " h, human fatigue " << data.humanFatiguePercent << "%.\n";
    out << "Sort supplies into four groups: life safety, repair-critical, useful comfort, and nonessential weight.\n";
    out << "Life safety includes drinking water, medical supplies, shelter temperature, light, communication, fire/smoke avoidance, and safe route choices.\n";
    out << "Repair-critical includes fuses, wire, tape, cordage, fasteners, hose clamps, zip ties, spare filters, basic hand tools, meter, chargers, and manuals.\n";
    if (data.waterLiters < 0.5 || data.foodHours < 3.0 || data.humanFatiguePercent >= 85.0) {
        out << "Scarcity note: survival mode indicators are present, so conserve energy, reduce movement, protect water, and defer nonessential projects.\n";
    }
    if (data.batteryPercent <= 20.0) {
        out << "Power note: battery is low, so prioritize sensing, silent alerts, communication, and essential motion over education or convenience tasks.\n";
    }
    out << "Logging habit: write down what was used, what failed, what must be replaced, and what should be improved before the next trip.";
    return out.str();
}

std::string ResourcefulnessModule::safeSubstitutionGuide() const {
    return joinLines({
        "Safe substitution guide",
        "Substitute by function, rating, and environment: load, temperature, water exposure, vibration, chemical exposure, and how failure behaves.",
        "Good temporary substitutes can include cordage for bundling, clean cloth for pre-filtering water before proper purification, spare containers for dry storage, brackets for non-structural mounting, and labeled low-voltage connectors.",
        "Do not substitute unknown wire, damaged extension cords, random chargers, wrong fuses, wrong battery chemistry, fuel containers, pressure parts, climbing/lifting hardware, brake parts, medical supplies, or food/plant IDs.",
        "Mark temporary fixes clearly, inspect them often, and replace them with proper parts as soon as possible."
    });
}

std::string ResourcefulnessModule::fieldRepairGuide() const {
    return joinLines({
        "Field repair guide",
        "Use a simple repair loop: make safe, isolate the fault, inspect visually, measure if possible, repair the smallest confirmed problem, test at low power, then monitor.",
        "Mechanical repairs: clean dirt first, tighten loose fasteners, reduce vibration, lubricate only where appropriate, protect moving parts, and avoid overloading cracked or bent parts.",
        "Electrical repairs: de-energize, verify off, check fuses/connectors/polarity, use correct wire size and insulation, keep repairs dry, and test with current limits before normal use.",
        "Water repairs: stop leaks, separate potable and non-potable systems, sanitize drinking containers, avoid chemical contamination, and purify unknown water before drinking.",
        "Stop conditions: smoke, heat, swelling batteries, fuel smell, arcing, structural cracking, pressure release, unknown chemicals, or any situation where a failed repair could injure someone."
    });
}

std::string ResourcefulnessModule::ruralSkillMap() const {
    return joinLines({
        "Rural self-reliance skill map",
        "Core skills to learn over time: basic first aid, water purification, weather reading, fire safety, low-voltage DC, meter use, knots, sewing, tool maintenance, garden soil care, composting, food storage, map reading, and radio/phone charging plans.",
        "Repair skills: cleaning contacts, replacing fuses, fixing cords only when safe and rated, tightening hardware, patching non-pressure hoses, sharpening hand tools, mending fabric, and documenting part numbers.",
        "Build skills: small shelves, tool racks, rain gauges, compost screens, garden irrigation timers, low-voltage lighting trainers, protected USB charging kits, and removable noninvasive wildlife-safe monitoring stations.",
        "Community skills matter too: know local electricians, mechanics, well/pump experts, wildlife rehab contacts, extension offices, neighbors, and emergency services before the emergency."
    });
}

std::string ResourcefulnessModule::ethicalBoundaries() const {
    return joinLines({
        "Resourcefulness ethical boundaries",
        "Never steal, trespass, damage habitat, strip working public equipment, pollute water, disturb cultural sites, or harm wildlife to get parts.",
        "Do not improvise weapons, traps, coercive devices, surveillance against people, unsafe animal restraints, or systems intended to intimidate.",
        "Do not experiment on humans, animals, drinking water, food safety, house wiring, fuel systems, pressure vessels, lifting systems, brakes, or life-support equipment.",
        "When uncertain, choose the reversible, non-harmful, low-energy option and ask for more observations before acting."
    });
}

std::string InventoryProjectPlannerModule::intakeTemplate() const {
    return joinLines({
        "Inventory intake template",
        "Tell me: project goal, available parts, available tools, power sources, ratings printed on parts, environment, weather exposure, who will use it, and what failure must never do.",
        "Helpful format: 'Goal: ... Parts: ... Tools: ... Power: ... Hazards: ... Must not: ...'",
        "Take photos/notes of labels, cracks, corrosion, swollen batteries, missing insulation, and unknown chemicals before choosing a project."
    });
}

std::string InventoryProjectPlannerModule::inventorySummary(const SensorData& data) const {
    std::ostringstream out;
    out << "Inventory summary\n";
    if (data.projectGoal.empty()) {
        out << "Project goal: not specified yet. Start by naming the job, not the parts.\n";
    } else {
        out << "Project goal: " << data.projectGoal << "\n";
    }

    if (data.inventoryItems.empty()) {
        out << "Structured inventory: none listed yet. Ask the owner to list parts, tools, ratings, condition, and hazards.\n";
        out << intakeTemplate();
        return out.str();
    }

    const auto powerParts = matchingItems(data.inventoryItems, {
        "battery", "solar", "charge", "charger", "controller", "inverter", "alternator",
        "motor", "generator", "wire", "fuse", "breaker", "switch", "led", "meter", "usb"
    });
    const auto mechanicalParts = matchingItems(data.inventoryItems, {
        "bolt", "screw", "bracket", "wheel", "bicycle", "bearing", "pulley", "belt", "hinge",
        "spring", "pipe", "tube", "tubing", "hose", "clamp", "wood", "panel", "sheet"
    });
    const auto containersAndMaterials = matchingItems(data.inventoryItems, {
        "bucket", "bottle", "barrel", "bin", "crate", "tarp", "cloth", "canvas", "jar",
        "screen", "mesh", "foam", "insulation", "box", "enclosure"
    });
    const auto tools = matchingItems(data.inventoryItems, {
        "multimeter", "meter", "drill", "saw", "solder", "wrench", "plier", "screwdriver",
        "crimper", "tape", "zip tie", "file", "clamp"
    });
    const auto hazards = matchingItems(data.inventoryItems, {
        "swollen", "leaking", "lithium", "microwave", "capacitor", "transformer", "crt",
        "asbestos", "fuel", "gasoline", "propane", "pressure", "chemical", "mains", "outlet",
        "breaker panel", "rusted", "cracked"
    });

    out << "Items listed (" << data.inventoryItems.size() << "): " << listItemsOrNone(data.inventoryItems) << "\n";
    out << "Power/electrical candidates: " << listItemsOrNone(powerParts) << "\n";
    out << "Mechanical/build candidates: " << listItemsOrNone(mechanicalParts) << "\n";
    out << "Containers/materials: " << listItemsOrNone(containersAndMaterials) << "\n";
    out << "Tools/support items: " << listItemsOrNone(tools) << "\n";
    out << "Hazard flags needing caution or removal: " << listItemsOrNone(hazards) << "\n";
    out << "Decision rule: unknown rating, unknown chemistry, cracks, corrosion, heat damage, or missing insulation moves a part into 'inspect before use'.";
    return out.str();
}

std::string InventoryProjectPlannerModule::projectPlanner(const SensorData& data) const {
    return joinLines({
        "Project planner",
        "1. Need: " + (data.projectGoal.empty() ? std::string("ask the owner to name the problem to solve.") : data.projectGoal),
        "2. Safety class: decide whether the project is low-risk learning, cautious field use, or off-limits without qualified help.",
        "3. Build path: sketch, parts list, risk list, low-power bench test, protected enclosure, labels, shutdown step, field test, and maintenance note.",
        "4. Failure plan: make sure failure becomes 'turns off safely' instead of fire, shock, injury, blocked movement, polluted water, or habitat damage.",
        "5. Owner decision point: explain safe options first, then ask the owner which low-risk project is most useful right now."
    });
}

std::string InventoryProjectPlannerModule::safeBuildIdeas(const SensorData& data) const {
    const auto powerParts = matchingItems(data.inventoryItems, {
        "battery", "solar", "charge", "charger", "controller", "motor", "wire", "fuse",
        "switch", "led", "meter", "usb"
    });
    const auto mechanicalParts = matchingItems(data.inventoryItems, {
        "bolt", "screw", "bracket", "wheel", "bicycle", "bearing", "pulley", "belt", "hinge",
        "pipe", "tube", "hose", "clamp", "wood", "panel", "sheet"
    });
    const auto containersAndMaterials = matchingItems(data.inventoryItems, {
        "bucket", "bottle", "barrel", "bin", "crate", "tarp", "cloth", "canvas", "jar",
        "screen", "mesh", "box", "enclosure"
    });

    std::vector<std::string> ideas;
    if (!powerParts.empty()) {
        ideas.push_back("low-voltage lighting trainer with fuse, switch, LED/load, labels, and shutdown step");
        ideas.push_back("USB charging station only with proper charge controller, correct fuse, enclosure, and matched battery chemistry");
        ideas.push_back("hand-crank or small motor generator demo that powers an LED/capacitor, not household wiring");
    }
    if (!mechanicalParts.empty()) {
        ideas.push_back("tool rack, repair bracket, garden cart improvement, pedal-powered mechanical demo, or low-speed pulley lesson");
        ideas.push_back("non-structural mount or protective guard after checking cracks, vibration, sharp edges, and load");
    }
    if (!containersAndMaterials.empty()) {
        ideas.push_back("parts organizer, weatherproof storage, seed-starting tray, compost sifter, hand-wash station, or non-potable plant-water container");
        ideas.push_back("cloth pre-filter holder for water before proper purification, clearly labeled as not sufficient by itself");
    }
    if (ideas.empty()) {
        ideas.push_back("start with a repair notebook, tool inventory, parts labels, maintenance checklist, and low-risk hand-tool project");
    }

    std::ostringstream out;
    out << "Safe build ideas from current inventory\n";
    for (const auto& idea : ideas) {
        out << "- " << idea << "\n";
    }
    out << "Choose the simplest useful project first, then test small before relying on it.";
    return out.str();
}

std::string InventoryProjectPlannerModule::doNotBuildWarnings(const SensorData& data) const {
    const auto hazardItems = matchingItems(data.inventoryItems, {
        "swollen", "leaking", "lithium", "microwave", "capacitor", "transformer", "crt",
        "asbestos", "fuel", "gasoline", "propane", "pressure", "chemical", "mains", "outlet",
        "breaker panel", "rusted", "cracked"
    });

    std::ostringstream out;
    out << "Do-not-build and caution list\n";
    if (!hazardItems.empty()) {
        out << "Flagged items: " << listItemsOrNone(hazardItems) << "\n";
        out << "Move flagged items out of the build plan until they are identified, discharged if applicable by qualified people, recycled, or handled under proper safety rules.\n";
    }
    out << "Do not build: weapons, traps, animal restraints, surveillance for spying, live mains wiring, grid/backfeed connections, fuel systems, pressure vessels, brakes, lifting/climbing gear, medical devices, food-safety shortcuts, or drinking-water shortcuts.\n";
    out << "Caution projects: battery banks, inverters, solar arrays, well pumps, generator transfer equipment, wind/water power, structural towers, heaters, and anything that could shock, burn, poison, collapse, or trap someone.";
    return out.str();
}

std::string InventoryProjectPlannerModule::projectLogTemplate() const {
    return joinLines({
        "Project log template",
        "Goal:",
        "Parts used and ratings:",
        "Parts rejected and why:",
        "Risks found:",
        "Protection added: fuse, enclosure, labels, strain relief, guards, ventilation, shutdown:",
        "Test result:",
        "Maintenance note:",
        "Next safer improvement:"
    });
}

std::string FieldCalculatorModule::calculatorSummary(const SensorData& data) const {
    return joinLines({
        "Field calculator summary",
        batteryRuntimeEstimate(data),
        solarHarvestEstimate(data),
        generatorLoadEstimate(data),
        waterDurationEstimate(data),
        rainCatchmentEstimate(data),
        gardenPlanningEstimate(data),
        calculatorSafetyNotes()
    });
}

std::string FieldCalculatorModule::batteryRuntimeEstimate(const SensorData& data) const {
    const double capacityWh = positiveOr(data.batteryCapacityWh, 240.0);
    const double loadWatts = positiveOr(data.electricalLoadWatts, 20.0);
    const double availableWh = capacityWh * std::clamp(data.batteryPercent, 0.0, 100.0) / 100.0;
    const double reserveAwareWh = availableWh * 0.8;
    const double runtimeHours = reserveAwareWh / loadWatts;

    std::ostringstream out;
    out << std::fixed << std::setprecision(1);
    out << "Battery runtime estimate: " << reserveAwareWh << " usable Wh from a " << capacityWh
        << " Wh battery at " << data.batteryPercent << "%, powering about " << loadWatts
        << " W, gives roughly " << runtimeHours << " hours while keeping a safety reserve.";
    if (runtimeHours < 4.0) {
        out << " Priority: reduce loads, dim lights, charge communication devices first, and keep safety sensors active.";
    }
    return out.str();
}

std::string FieldCalculatorModule::solarHarvestEstimate(const SensorData& data) const {
    const double panelWatts = positiveOr(data.solarPanelWatts, 100.0);
    const double sunHours = positiveOr(data.sunHours, 4.0);
    const double dailyWh = panelWatts * sunHours * 0.7;
    const double loadWatts = positiveOr(data.electricalLoadWatts, 20.0);
    const double supportedHours = dailyWh / loadWatts;

    std::ostringstream out;
    out << std::fixed << std::setprecision(1);
    out << "Solar estimate: " << panelWatts << " W panel x " << sunHours
        << " sun hours x 70% field efficiency is about " << dailyWh
        << " Wh/day, enough for roughly " << supportedHours << " hours at "
        << loadWatts << " W.";
    out << " Keep panels secure, dry at connectors, shaded as little as possible, and routed through a proper charge controller.";
    return out.str();
}

std::string FieldCalculatorModule::generatorLoadEstimate(const SensorData& data) const {
    const double outputWatts = positiveOr(data.generatorOutputWatts, 800.0);
    const double loadWatts = positiveOr(data.electricalLoadWatts, 20.0);
    const double conservativeContinuousWatts = outputWatts * 0.8;
    const double marginWatts = conservativeContinuousWatts - loadWatts;

    std::ostringstream out;
    out << std::fixed << std::setprecision(1);
    out << "Generator load estimate: for an " << outputWatts
        << " W generator, a conservative continuous target is about "
        << conservativeContinuousWatts << " W. Planned load is " << loadWatts
        << " W, leaving about " << marginWatts << " W margin.";
    if (marginWatts < 0.0) {
        out << " This is overloaded: shed loads before use.";
    }
    out << " Never backfeed a home, never run fuel engines indoors or near openings, and use manufacturer instructions plus proper transfer equipment for real home power.";
    return out.str();
}

std::string FieldCalculatorModule::waterDurationEstimate(const SensorData& data) const {
    const int people = std::max(1, data.peopleCount);
    const double dailyNeed = positiveOr(data.dailyWaterNeedLiters, 3.0) * people;
    const double days = data.waterLiters / dailyNeed;

    std::ostringstream out;
    out << std::fixed << std::setprecision(1);
    out << "Water duration estimate: " << data.waterLiters << " L available for "
        << people << " people at " << dailyNeed << " L/day total gives about "
        << days << " days.";
    if (days < 1.0) {
        out << " Priority: reduce exertion, seek safe water, purify before drinking, and reserve water for humans first.";
    }
    return out.str();
}

std::string FieldCalculatorModule::rainCatchmentEstimate(const SensorData& data) const {
    const double area = positiveOr(data.rainCatchmentAreaM2, 4.0);
    const double rainfall = std::max(0.0, data.rainfallMm);
    const double liters = area * rainfall * 0.8;

    std::ostringstream out;
    out << std::fixed << std::setprecision(1);
    out << "Rain catchment estimate: " << area << " m2 catchment x "
        << rainfall << " mm rain x 80% collection efficiency could collect about "
        << liters << " L.";
    out << " Treat collected rain as non-potable until filtered/purified and stored in clean, labeled containers.";
    return out.str();
}

std::string FieldCalculatorModule::gardenPlanningEstimate(const SensorData& data) const {
    const double area = positiveOr(data.gardenAreaM2, 10.0);
    const double denseGreens = area * 9.0;
    const double largerPlants = area * 2.0;

    std::ostringstream out;
    out << std::fixed << std::setprecision(0);
    out << "Garden planning estimate: " << area
        << " m2 can roughly hold about " << denseGreens
        << " small greens/herbs or about " << largerPlants
        << " larger plants, depending on crop, soil, water, and season.";
    out << " Keep soil covered, compost gently, avoid overwatering, and choose region-appropriate crops.";
    return out.str();
}

std::string FieldCalculatorModule::calculatorSafetyNotes() const {
    return joinLines({
        "Calculator safety notes",
        "These are rough planning estimates, not engineering certification.",
        "Electrical, generator, solar, battery, water, food, and garden calculations must be checked against real labels, meters, local conditions, local codes, and qualified help for high-risk systems.",
        "When the estimate is uncertain, choose the lower-load, lower-risk, more conservative plan."
    });
}

std::string MaintenanceScheduleModule::maintenanceOverview(const SensorData& data) const {
    std::ostringstream out;
    out << "Maintenance overview\n";
    out << "Use maintenance as prevention: small checks keep water, power, tools, medical supplies, food, shelter, and communication from failing during bad weather.\n";
    out << "Current flags: battery " << data.batteryPercent << "%, water " << data.waterLiters
        << " L, food estimate " << data.foodHours << " h, fatigue "
        << data.humanFatiguePercent << "%, terrain " << toString(data.terrain) << ".\n";
    out << nextMaintenancePriorities(data);
    return out.str();
}

std::string MaintenanceScheduleModule::weeklyChecklist() const {
    return joinLines({
        "Weekly maintenance checklist",
        "Check drinking water quantity, container cleanliness, leaks, filters, and purification supplies.",
        "Charge/test communication devices, lights, power banks, low-voltage battery packs, and CO/smoke alarms.",
        "Inspect first-aid kit, gloves, clean dressings, medications if applicable, and emergency contact notes.",
        "Walk the property/camp for animal signs, standing water, damaged fences, loose gear, trip hazards, and new erosion.",
        "Clean and put away hand tools, sharpen/inspect safe cutting tools, and restock common fasteners, tape, cordage, fuses, and labels."
    });
}

std::string MaintenanceScheduleModule::monthlyChecklist() const {
    return joinLines({
        "Monthly maintenance checklist",
        "Review inventory, project logs, manuals, maps, battery labels, spare parts, and report/memory archives.",
        "Inspect cords, connectors, low-voltage wiring, enclosures, strain relief, fuses, and signs of heat or corrosion.",
        "Rotate pantry food, inspect pest-resistant storage, check seed storage, and refresh animal-safe food/waste practices.",
        "Clean or replace filters by manufacturer guidance, inspect gutters/catchment, and sanitize water containers when appropriate.",
        "Run scenario drills: medical, fire/smoke, weather shift, low resources, lost route, and owner command/report checks."
    });
}

std::string MaintenanceScheduleModule::seasonalChecklist(const SensorData& data) const {
    std::vector<std::string> lines{
        "Seasonal maintenance checklist",
        "Before heat: shade, ventilation, extra water, battery heat protection, garden mulch, and reduced-exertion plans.",
        "Before cold: insulation, dry clothing, water freeze protection, safe heat plan, charged lights, and shelter checks.",
        "Before storm/fire season: clear legal defensible space, secure loose items, check evacuation routes, review smoke/CO alarms, and prepare go-bags.",
        "Before planting/harvest: soil test, compost, mulch, crop plan, water plan, seed inventory, tool readiness, and wildlife-friendly boundaries."
    };
    if (data.rapidWeatherShift || data.windKph >= 45.0) {
        lines.push_back("Current weather cue: move storm and loose-gear checks to today.");
    }
    if (data.terrain == TerrainType::Desert) {
        lines.push_back("Desert emphasis: water storage, shade cloth, dust protection, battery heat limits, and low-water crops.");
    } else if (data.terrain == TerrainType::Forest) {
        lines.push_back("Forest emphasis: deadfall checks, fire awareness, trail drainage, food storage, and wildlife distance.");
    } else if (data.terrain == TerrainType::Snow) {
        lines.push_back("Snow emphasis: freeze protection, insulation, traction, roof/shelter load, and dry backup clothing.");
    } else if (data.terrain == TerrainType::Rocky) {
        lines.push_back("Rocky emphasis: slope stability, rockfall checks, footwear, water seep awareness, and protected containers.");
    }
    return joinVectorLines(lines);
}

std::string MaintenanceScheduleModule::emergencyResetChecklist() const {
    return joinLines({
        "Emergency reset checklist",
        "After any emergency, check people first: breathing, bleeding, shock signs, warmth, hydration, and group count.",
        "Then check hazards: fire/smoke, CO, fuel, damaged batteries, downed wires, unstable structures, contaminated water, sharp debris, and aggressive/stressed animals.",
        "Then restore systems in order: communication, light, safe water, shelter temperature, medical supplies, food, tools, then comfort tasks.",
        "Log what happened, what was used, what failed, what must be replaced, and what should be practiced."
    });
}

std::string MaintenanceScheduleModule::nextMaintenancePriorities(const SensorData& data) const {
    std::vector<std::string> priorities;
    if (data.batteryPercent <= 25.0) {
        priorities.push_back("charge batteries and reduce nonessential electrical loads");
    }
    if (data.waterLiters < std::max(1, data.peopleCount) * data.dailyWaterNeedLiters) {
        priorities.push_back("increase safe water storage or locate/purify more water");
    }
    if (data.foodHours < 6.0) {
        priorities.push_back("review food plan and preserve energy before foraging or travel");
    }
    if (data.smokeDetected || data.fireDetected) {
        priorities.push_back("treat fire/smoke readiness and evacuation route checks as immediate");
    }
    if (data.rapidWeatherShift || data.windKph >= 45.0) {
        priorities.push_back("secure shelter, tools, solar panels, and loose containers before weather worsens");
    }
    if (!data.inventoryItems.empty()) {
        priorities.push_back("label inventory items, reject unsafe parts, and update project logs");
    }
    if (priorities.empty()) {
        priorities.push_back("keep routine weekly checks, rotate supplies, and practice one small safety drill");
    }

    std::ostringstream out;
    out << "Next maintenance priorities: ";
    for (std::size_t i = 0; i < priorities.size(); ++i) {
        if (i > 0) {
            out << "; ";
        }
        out << priorities[i];
    }
    out << ".";
    return out.str();
}

std::string HardwareInterfaceModule::interfaceOverview(const SensorData& data) const {
    std::ostringstream out;
    out << "Hardware interface overview\n";
    out << "Mode: " << (data.realHardwareMode ? "real hardware mode requested" : "demo/training mode") << ". ";
    out << "Interface connection: " << (data.hardwareInterfaceConnected ? "connected" : "not connected") << ".\n";
    out << "This layer is a safety bridge between the guardian brain and real parts. It should read sensors, report health, command only safe motion, and fail to stop on bad data.\n";
    out << "Until a real microcontroller/robot controller reports verified hardware status, the bot must treat hardware actions as advisory simulation only.";
    return out.str();
}

std::string HardwareInterfaceModule::requiredInputsAndOutputs() const {
    return joinLines({
        "Hardware interface skeleton: required inputs and outputs",
        "Inputs: emergency stop circuit, owner authentication signal, battery monitor, solar charge controller, temperature/weather/smoke sensors, obstacle sensor, GPS/location, geofence/map, IMU/tilt/compass, payload/load, camera, thermal camera, infrared/IR motion or heat-signature status, non-invasive medical request input, water/filter storage status, food storage status, communication link, and owner alert link.",
        "Outputs: private owner alert, motor enable, speed limit, steering target, stop command, light/sound alert, report log, communication message draft, and safe shutdown request.",
        "All outputs must be bounded: low speed by default, no pushing through obstacles, no pursuit behavior, no harmful tools, and no movement if owner/family location is uncertain.",
        "The safest default for any missing, stale, or contradictory hardware data is stop motion, keep alerts available, and ask for owner/family verification."
    });
}

std::string HardwareInterfaceModule::sensorCheckReport(const SensorData& data) const {
    std::vector<std::string> lines{
        "Sensor check report"
    };

    const auto add = [&lines](const std::string& name, bool ok, const std::string& note) {
        lines.push_back("- " + name + ": " + (ok ? "OK" : "NEEDS CHECK") + " - " + note);
    };

    add("Battery monitor", data.batteryMonitorOk, "required for survival mode, self-preserve, charging safety, and runtime estimates.");
    add("Solar charge controller", data.solarChargeControllerOk || !data.solarPanelConnected, "required before solar panels charge a battery or power bank.");
    add("GPS/location", data.gpsOk && data.locationKnown, "required for route reports, safe zones, camp memory, and emergency communication.");
    add("IMU/tilt", data.imuOk, "required to detect falls, unsafe slope, stuck posture, or rollover risk.");
    add("Geofence/map", data.geofenceConfigured, "required before any real route-following or patrol movement.");
    add("Payload/load", data.payloadKg <= 20.0, "required to refuse unsafe carrying loads and protect stability.");
    add("Obstacle sensor", data.obstacleSensorOk, "required before any real autonomous movement.");
    add("Camera", data.cameraOk, "advisory only; privacy rules and owner/family consent still apply.");
    add("Thermal camera", data.thermalCameraOk, "useful for heat signatures, people/pet detection, and fire risk, but never for stalking or privacy invasion.");
    add("Infrared/IR sensor", data.infraredSensorOk, "useful for low-light motion, heat-signature cues, and night awareness; advisory only and privacy-limited.");
    add("Smoke/fire sensor", data.smokeSensorOk, "important for fire escape and camp safety.");
    add("Weather sensor", data.weatherSensorOk, "supports heat, cold, wind, humidity, and storm awareness.");
    add("Medical request input", data.voiceInterfaceConfigured || data.phoneAlertConfigured || data.sensorDriverBridgeOnline, "supports non-invasive requests for first-aid guidance and vitals prompts.");
    add("Water filter/storage status", data.waterFilterAvailable || data.cleanWaterContainersAvailable, "tracks readiness for filtering and clean water storage; does not certify potability.");
    add("Food drying/storage status", data.foodDryingAvailable || data.dryFoodStorageAvailable, "tracks pantry readiness and spoilage risk; does not certify unsafe food.");
    add("Communication link", data.communicationLinkOk, "required for emergency messages, reports, and owner/family alerts.");
    add("Owner alert link", data.ownerAlertLinkOk, "required for silent private warnings.");
    return joinVectorLines(lines);
}

std::string HardwareInterfaceModule::actuatorCheckReport(const SensorData& data) const {
    std::vector<std::string> lines{
        "Actuator and motion check report"
    };

    const auto add = [&lines](const std::string& name, bool ok, const std::string& note) {
        lines.push_back("- " + name + ": " + (ok ? "OK" : "NEEDS CHECK") + " - " + note);
    };

    add("Emergency stop circuit", data.emergencyStopCircuitOk, "must cut motion safely and be physically reachable before field movement.");
    add("Safe stop on fault", data.safeStopOnFaultOk, "motors must stop on lost signal, stale sensors, low battery, tip/fall, or blocked motion.");
    add("Motor controller", data.motorControllerOk, "must support speed limits, current limits, braking/stop, and command timeout.");
    add("Drive base", data.driveBaseOk, "wheels/tracks/legs must move slowly, quietly, and predictably without blocking people.");
    add("Steering", data.steeringOk, "must turn smoothly and respect route limits.");
    add("Light/sound output", data.speakerLightOk, "must be non-harmful, low intensity by default, and used only for owner alerts, signaling, or gentle deterrence.");
    add("Geofence/no-go zones", data.geofenceConfigured, "should prevent entry into roads, cliffs, private restricted areas, sensitive habitat, and unsafe water edges.");
    return joinVectorLines(lines);
}

std::string HardwareInterfaceModule::failsafeCheckReport(const SensorData& data) const {
    std::vector<std::string> gaps;
    if (!data.emergencyStopCircuitOk) {
        gaps.push_back("physical emergency stop");
    }
    if (!data.safeStopOnFaultOk) {
        gaps.push_back("safe stop on fault");
    }
    if (!data.ownerAuthenticated) {
        gaps.push_back("owner authentication");
    }
    if (!data.communicationLinkOk || !data.ownerAlertLinkOk) {
        gaps.push_back("private owner/family alert path");
    }
    if (!data.batteryMonitorOk) {
        gaps.push_back("battery monitor");
    }
    if (!data.obstacleSensorOk) {
        gaps.push_back("obstacle sensing");
    }

    std::ostringstream out;
    out << "Hardware failsafe check\n";
    if (gaps.empty()) {
        out << "Core failsafe signals are present in this simulated status. Continue bench testing before field use.";
    } else {
        out << "Missing or unverified: " << listItemsOrNone(gaps) << ". Real movement should stay disabled until these are fixed.";
    }
    out << "\nRequired failure behavior: stop motion, keep the bot stable, preserve owner/family alerts, log the fault, and wait for verified owner input.";
    return out.str();
}

std::string HardwareInterfaceModule::fieldTestSequence() const {
    return joinLines({
        "Hardware bench-to-field test sequence",
        "1. Desk test: no motors attached. Verify sensor readings, owner authentication, private alerts, reports, and shutdown commands.",
        "2. Lifted-wheel test: motors off the ground. Verify speed limits, stop command, command timeout, and safe stop on sensor loss.",
        "3. Low-speed indoor test: clear area, human spotter, emergency stop in hand, no autonomous movement near stairs, pets, children, or obstacles.",
        "4. Controlled outdoor test: flat open area, geofence/no-go zones, low speed, return-to-owner, stop-on-fault, and full report logging.",
        "5. Field advisory mode: allow guidance and alerts first; enable movement only after repeated no-fault tests and qualified review.",
        "If any test fails, stop, log it, repair it, and repeat earlier tests before moving forward."
    });
}

std::string HardwareInterfaceModule::readinessDecision(const SensorData& data) const {
    const bool sensorsReady = data.batteryMonitorOk
        && data.gpsOk
        && data.imuOk
        && data.obstacleSensorOk
        && data.smokeSensorOk
        && data.weatherSensorOk
        && data.communicationLinkOk
        && data.ownerAlertLinkOk;
    const bool motionReady = data.emergencyStopCircuitOk
        && data.safeStopOnFaultOk
        && data.motorControllerOk
        && data.driveBaseOk
        && data.steeringOk
        && data.geofenceConfigured;

    if (!data.hardwareInterfaceConnected) {
        return "Hardware readiness decision: demo/training only. No real hardware interface is connected, so the bot can advise and simulate but must not claim physical readiness.";
    }
    if (!data.realHardwareMode) {
        return "Hardware readiness decision: interface signals are being reviewed in demo mode. Keep motors disabled until real hardware mode is intentionally enabled by the owner.";
    }
    if (sensorsReady && motionReady) {
        return "Hardware readiness decision: bench-test ready only. Run the full test sequence and qualified review before field autonomy.";
    }
    return "Hardware readiness decision: not field-ready. Keep real movement disabled and use advisory mode until every required sensor, actuator, owner-alert, and failsafe check passes.";
}

std::string OwnerProfileModule::buildOwnerProfile(const SensorData& data) const {
    std::ostringstream out;
    out << "CONSERVATION GUARDIAN OWNER PROFILE\n";
    out << "Keep private: this may include family names, medical notes, allergies, safe words, contacts, and home/camp region.\n\n";
    out << "IDENTITY\n";
    out << "Owner display name: " << (data.ownerDisplayName.empty() ? "owner" : data.ownerDisplayName) << "\n";
    out << "Family/group names: " << listItemsOrNone(data.familyNames) << "\n";
    out << "People currently expected: " << data.peopleCount << "\n\n";

    out << "SAFETY WORDS AND AUTHENTICATION HINTS\n";
    out << "Owner safe words or check-in phrases: " << listItemsOrNone(data.ownerSafeWords) << "\n";
    out << "Authentication status now: " << (data.ownerAuthenticated ? "verified in current sensor data" : "not verified in current sensor data") << "\n";
    out << "Rule: safe words are hints for owner/family workflow, not the only authentication method for shutdown, override, or machine-stop controls.\n\n";

    out << "MEDICAL AND CARE NOTES\n";
    out << "Allergies: " << listItemsOrNone(data.ownerAllergies) << "\n";
    out << "Medical/care notes: " << listItemsOrNone(data.ownerMedicalNotes) << "\n";
    out << "Privacy rule: share medical notes only with owner/family or emergency responders when necessary for care.\n\n";

    out << "REGION AND CONTACTS\n";
    out << "Home region: " << (data.homeRegion.empty() ? "not recorded" : data.homeRegion) << "\n";
    out << "Camp/base region: " << (data.campRegion.empty() ? "not recorded" : data.campRegion) << "\n";
    out << "Emergency contacts: " << listItemsOrNone(data.emergencyContacts) << "\n";
    out << "Owner privacy rules: " << (data.ownerPrivacyRules.empty() ? "default: keep owner/family location, medical, route, security, and resource details private" : data.ownerPrivacyRules) << "\n\n";

    out << profileGaps(data) << "\n";
    out << profilePrivacyPolicy() << "\n";
    return out.str();
}

bool OwnerProfileModule::saveOwnerProfile(const std::string& filePath, const SensorData& data, std::string& status) const {
    return writeTextFile(filePath, buildOwnerProfile(data), status, "Owner profile");
}

bool OwnerProfileModule::loadOwnerProfileText(const std::string& filePath, std::string& contents, std::string& status) const {
    return readTextFile(filePath, contents, status, "Owner profile");
}

std::string OwnerProfileModule::profileGaps(const SensorData& data) const {
    std::vector<std::string> gaps;
    if (!data.ownerProfileConfigured) {
        gaps.push_back("mark owner profile as configured after owner review");
    }
    if (data.ownerDisplayName.empty() || data.ownerDisplayName == "owner") {
        gaps.push_back("owner display name or private owner ID");
    }
    if (data.familyNames.empty() && data.peopleCount > 1) {
        gaps.push_back("family/group names or private IDs");
    }
    if (data.ownerSafeWords.empty()) {
        gaps.push_back("safe words/check-in phrases");
    }
    if (data.ownerAllergies.empty()) {
        gaps.push_back("allergies or 'none known'");
    }
    if (data.ownerMedicalNotes.empty()) {
        gaps.push_back("medical/care notes or 'none recorded'");
    }
    if (data.emergencyContacts.empty()) {
        gaps.push_back("emergency contacts");
    }
    if (data.homeRegion.empty() && data.campRegion.empty()) {
        gaps.push_back("home/camp region");
    }
    if (data.ownerPrivacyRules.empty()) {
        gaps.push_back("owner privacy rules");
    }

    if (gaps.empty()) {
        return "Owner profile gaps: no obvious gaps from current data. Reconfirm after region changes, medical changes, or group changes.";
    }
    return "Owner profile gaps to fill: " + listItemsOrNone(gaps) + ".";
}

std::string OwnerProfileModule::emergencyCareCard(const SensorData& data) const {
    std::ostringstream out;
    out << "Emergency care card\n";
    out << "Owner/family: " << (data.ownerDisplayName.empty() ? "owner" : data.ownerDisplayName);
    if (!data.familyNames.empty()) {
        out << " with " << listItemsOrNone(data.familyNames);
    }
    out << "\nAllergies: " << listItemsOrNone(data.ownerAllergies) << "\n";
    out << "Care notes: " << listItemsOrNone(data.ownerMedicalNotes) << "\n";
    out << "Emergency contacts: " << listItemsOrNone(data.emergencyContacts) << "\n";
    out << "Location context: " << (data.locationKnown ? data.locationDescription : "unknown") << "\n";
    out << "Share only the minimum needed for emergency care.";
    return out.str();
}

std::string OwnerProfileModule::profilePrivacyPolicy() const {
    return "Owner profile privacy policy: profile details are owner/family private, may guide safety decisions, and should be shared outside the group only for emergency care, rescue, or explicit owner-approved logging.";
}

int FieldReadinessModule::readinessScore(const SensorData& data) const {
    int score = 0;
    if (data.ownerProfileConfigured) {
        score += 10;
    }
    if (data.ownerAuthenticated) {
        score += 5;
    }
    if (data.realOwnerAuthenticationConfigured && data.securityKeysConfigured && data.trustedControllerPresent) {
        score += 5;
    }
    if (!data.emergencyContacts.empty()) {
        score += 5;
    }
    if (data.localKnowledgePackLoaded) {
        score += 10;
    }
    if (data.localWaterAdvisoriesChecked && data.waterQualityVerificationAvailable) {
        score += 5;
    }
    if (data.automatedTestsPassed) {
        score += 15;
    }
    if (data.hardwareInterfaceConnected) {
        score += 10;
    }
    if (data.emergencyStopCircuitOk && data.safeStopOnFaultOk) {
        score += 15;
    }
    if (data.batteryMonitorOk && data.gpsOk && data.imuOk && data.obstacleSensorOk && data.smokeSensorOk && data.weatherSensorOk) {
        score += 15;
    }
    if (data.communicationLinkOk && data.ownerAlertLinkOk && data.geofenceConfigured) {
        score += 10;
    }
    if (data.solarChargeControllerOk && data.solarBmsTelemetryOk) {
        score += 5;
    }
    if (data.privateStorageConfigured && data.privateStorageEncryptionActive && data.privateStorageAccessAuditOk) {
        score += 5;
    }
    if (data.mechanicalInspectionPassed && data.weatherproofingOk && data.cableStrainReliefOk && data.batteryFireSafetyOk && data.pinchPointGuardsOk) {
        score += 10;
    }
    if (data.benchTestsPassed) {
        score += 3;
    }
    if (data.controlledOutdoorTestsPassed) {
        score += 1;
    }
    if (data.qualifiedReviewCompleted) {
        score += 1;
    }
    if (data.fieldRiskAssessmentCompleted) {
        score += 1;
    }
    return std::clamp(score, 0, 100);
}

std::string FieldReadinessModule::readinessLevel(const SensorData& data) const {
    if (!data.automatedTestsPassed) {
        return "demo/training only: automated tests are not marked as passed in the current profile.";
    }
    if (!data.ownerProfileConfigured) {
        return "demo/training only: owner profile is incomplete.";
    }
    if (!data.localKnowledgePackLoaded) {
        return "demo/training only: local knowledge pack is not loaded.";
    }
    if (!data.realOwnerAuthenticationConfigured || !data.securityKeysConfigured || !data.trustedControllerPresent) {
        return "demo/training only: real owner authentication and trusted controller are incomplete.";
    }
    if (!data.privateStorageEncryptionActive) {
        return "demo/training only: private storage encryption is not active.";
    }
    if (!data.hardwareInterfaceConnected) {
        return "demo/training only: no real hardware interface is connected.";
    }
    if (!data.realHardwareMode) {
        return "bench-test planning: hardware signals exist, but real hardware mode is not enabled.";
    }
    if (!(data.emergencyStopCircuitOk && data.safeStopOnFaultOk && data.batteryMonitorOk && data.obstacleSensorOk && data.communicationLinkOk && data.ownerAlertLinkOk)) {
        return "not field-ready: one or more critical failsafe, battery, obstacle, communication, or owner-alert checks are missing.";
    }
    if (!(data.solarChargeControllerOk && data.solarBmsTelemetryOk && data.localWaterAdvisoriesChecked && data.waterQualityVerificationAvailable)) {
        return "not field-ready: solar/BMS charging telemetry or water verification is incomplete.";
    }
    if (!(data.mechanicalInspectionPassed && data.weatherproofingOk && data.cableStrainReliefOk && data.batteryFireSafetyOk && data.pinchPointGuardsOk)) {
        return "not field-ready: mechanical safety, weatherproofing, cable strain relief, battery fire safety, or pinch-point guarding is incomplete.";
    }
    if (!data.benchTestsPassed) {
        return "bench-test ready: run desk and lifted-wheel tests before outdoor movement.";
    }
    if (!data.controlledOutdoorTestsPassed) {
        return "controlled outdoor test ready: use low speed, a spotter, clear terrain, and emergency stop in hand.";
    }
    if (!data.qualifiedReviewCompleted) {
        return "field advisory candidate: controlled tests passed, but qualified review is still needed before relying on autonomy.";
    }
    if (!data.fieldRiskAssessmentCompleted) {
        return "field advisory candidate: qualified review is present, but site-specific field risk assessment is still needed.";
    }
    return "field advisory ready: still use conservative limits, owner supervision, and mission-safe behavior.";
}

std::string FieldReadinessModule::missingReadinessItems(const SensorData& data) const {
    std::vector<std::string> missing;
    if (!data.ownerProfileConfigured) {
        missing.push_back("owner profile");
    }
    if (data.emergencyContacts.empty()) {
        missing.push_back("emergency contacts");
    }
    if (!data.localKnowledgePackLoaded) {
        missing.push_back("local knowledge pack");
    }
    if (!data.localWaterAdvisoriesChecked) {
        missing.push_back("current water advisories checked");
    }
    if (!data.waterQualityVerificationAvailable) {
        missing.push_back("water quality verification kit/process");
    }
    if (!data.automatedTestsPassed) {
        missing.push_back("automated behavior tests");
    }
    if (!data.realOwnerAuthenticationConfigured || !data.securityKeysConfigured || !data.trustedControllerPresent) {
        missing.push_back("real owner authentication, security keys, and trusted controller");
    }
    if (!data.privateStorageEncryptionActive) {
        missing.push_back("active encrypted private storage");
    }
    if (!data.hardwareInterfaceConnected) {
        missing.push_back("hardware interface connection");
    }
    if (!data.realHardwareMode) {
        missing.push_back("intentional real-hardware mode");
    }
    if (!data.emergencyStopCircuitOk) {
        missing.push_back("physical emergency stop");
    }
    if (!data.safeStopOnFaultOk) {
        missing.push_back("safe stop on fault");
    }
    if (!data.batteryMonitorOk) {
        missing.push_back("battery monitor");
    }
    if (!data.solarChargeControllerOk || !data.solarBmsTelemetryOk) {
        missing.push_back("solar charge controller and BMS telemetry");
    }
    if (!data.gpsOk) {
        missing.push_back("GPS/location check");
    }
    if (!data.imuOk) {
        missing.push_back("IMU/tilt check");
    }
    if (!data.obstacleSensorOk) {
        missing.push_back("obstacle sensor");
    }
    if (!data.communicationLinkOk || !data.ownerAlertLinkOk) {
        missing.push_back("communication and private owner-alert links");
    }
    if (!data.geofenceConfigured) {
        missing.push_back("geofence/no-go zones");
    }
    if (!data.benchTestsPassed) {
        missing.push_back("bench tests");
    }
    if (!data.controlledOutdoorTestsPassed) {
        missing.push_back("controlled outdoor tests");
    }
    if (!data.mechanicalInspectionPassed || !data.weatherproofingOk || !data.cableStrainReliefOk || !data.batteryFireSafetyOk || !data.pinchPointGuardsOk) {
        missing.push_back("mechanical, weatherproofing, cable, battery fire, and pinch-point safety inspection");
    }
    if (!data.qualifiedReviewCompleted) {
        missing.push_back("qualified review for high-risk hardware/navigation claims");
    }
    if (!data.fieldRiskAssessmentCompleted) {
        missing.push_back("site-specific field risk assessment");
    }

    if (missing.empty()) {
        return "Missing readiness items: none obvious from the current simulated status. Continue periodic checks.";
    }
    return "Missing readiness items: " + listItemsOrNone(missing) + ".";
}

std::string FieldReadinessModule::nextSteps(const SensorData& data) const {
    std::vector<std::string> steps;
    if (!data.ownerProfileConfigured) {
        steps.push_back("finish owner/family profile, emergency contacts, allergies, safe words, and privacy rules");
    }
    if (!data.localKnowledgePackLoaded) {
        steps.push_back("load local plants, wildlife, fishing rules, land rules, weather risks, water advisories, and maps");
    }
    if (!data.localWaterAdvisoriesChecked || !data.waterQualityVerificationAvailable) {
        steps.push_back("add a water-verification process: current advisories, clean containers, correct treatment, and water test kit/process where appropriate");
    }
    if (!data.automatedTestsPassed) {
        steps.push_back("run automated behavior tests after each code change");
    }
    if (!data.realOwnerAuthenticationConfigured || !data.securityKeysConfigured || !data.trustedControllerPresent) {
        steps.push_back("configure real owner-only authentication with security keys/trusted controller and tested lockout behavior");
    }
    if (!data.privateStorageEncryptionActive) {
        steps.push_back("replace demo plain-text private files with active reviewed encryption and owner-held keys before real use");
    }
    if (!data.hardwareInterfaceConnected || !data.realHardwareMode) {
        steps.push_back("keep the bot in advisory/demo mode while hardware interface work is incomplete");
    }
    if (!data.solarChargeControllerOk || !data.solarBmsTelemetryOk || !data.batteryMonitorOk) {
        steps.push_back("prove solar charge controller, BMS telemetry, battery monitor, overcharge/overcurrent disconnect, and temperature fault behavior");
    }
    if (!data.emergencyStopCircuitOk || !data.safeStopOnFaultOk) {
        steps.push_back("prove physical emergency stop and safe-stop-on-fault before any motion");
    }
    if (!data.mechanicalInspectionPassed || !data.weatherproofingOk || !data.cableStrainReliefOk || !data.batteryFireSafetyOk || !data.pinchPointGuardsOk) {
        steps.push_back("finish mechanical inspection: stable base, weatherproofing, cable strain relief, battery fire protection, guards, payload limits, and no sharp/pinch hazards");
    }
    if (!data.benchTestsPassed) {
        steps.push_back("complete desk and lifted-wheel bench tests");
    }
    if (!data.controlledOutdoorTestsPassed) {
        steps.push_back("complete low-speed controlled outdoor tests with a spotter");
    }
    if (!data.qualifiedReviewCompleted) {
        steps.push_back("get qualified review for electrical, motion, battery, and navigation safety");
    }
    if (!data.fieldRiskAssessmentCompleted) {
        steps.push_back("complete a site-specific field risk assessment before relying on field autonomy");
    }
    if (steps.empty()) {
        steps.push_back("continue supervised field advisory use, periodic maintenance, and conservative safety limits");
    }
    return "Next readiness steps: " + listItemsOrNone(steps) + ".";
}

std::string FieldReadinessModule::readinessReport(const SensorData& data) const {
    std::ostringstream out;
    out << "Field readiness report\n";
    out << "Field readiness score: " << readinessScore(data) << "/100.\n";
    out << "Readiness level: " << readinessLevel(data) << "\n";
    out << missingReadinessItems(data) << "\n";
    out << nextSteps(data) << "\n";
    out << "Rule: a high score is not permission for unsafe autonomy. Human safety, owner supervision, emergency stop, privacy, and conservation remain mandatory.";
    return out.str();
}

std::string RealWorldDeploymentModule::deploymentGate(const SensorData& data) const {
    std::vector<std::string> blockers;
    if (!data.realHardwareMode || !data.hardwareInterfaceConnected || !data.hardwareDriversInstalled) {
        blockers.push_back("real hardware interface and driver installation are incomplete");
    }
    if (!data.emergencyStopCircuitOk || !data.safeStopOnFaultOk) {
        blockers.push_back("physical emergency stop and safe-stop-on-fault are not both proven");
    }
    if (!data.realOwnerAuthenticationConfigured || !data.securityKeysConfigured || !data.trustedControllerPresent) {
        blockers.push_back("real owner authentication is not fully configured");
    }
    if (!data.privateStorageEncryptionActive) {
        blockers.push_back("private storage encryption is not active");
    }
    if (!data.localKnowledgePackLoaded || !data.localWaterAdvisoriesChecked || !data.waterQualityVerificationAvailable) {
        blockers.push_back("local knowledge, water advisories, or water verification are incomplete");
    }
    if (!data.solarChargeControllerOk || !data.solarBmsTelemetryOk || !data.batteryMonitorOk) {
        blockers.push_back("solar charge controller, BMS telemetry, or battery monitor is incomplete");
    }
    if (!data.mechanicalInspectionPassed || !data.weatherproofingOk || !data.cableStrainReliefOk || !data.batteryFireSafetyOk || !data.pinchPointGuardsOk) {
        blockers.push_back("mechanical enclosure, weatherproofing, cable strain relief, battery fire safety, or pinch-point guards are incomplete");
    }
    if (!data.automatedTestsPassed || !data.benchTestsPassed || !data.controlledOutdoorTestsPassed || !data.fieldRiskAssessmentCompleted || !data.qualifiedReviewCompleted) {
        blockers.push_back("test progression, field risk assessment, or qualified review is incomplete");
    }

    if (blockers.empty()) {
        return "Real-world deployment gate: supervised field advisory use may be considered. Continue low-speed limits, owner supervision, emergency-stop access, privacy protection, and conservative retreat-first behavior.";
    }
    return "Real-world deployment gate: demo/training mode only. Blockers: " + listItemsOrNone(blockers) + ".";
}

std::string RealWorldDeploymentModule::hardwareAdapterRequirements(const SensorData& data) const {
    std::ostringstream out;
    out << "Real hardware adapter requirements\n";
    out << "- Required live inputs: GPS/location " << (data.gpsOk ? "OK" : "missing")
        << ", IMU/compass " << (data.imuOk ? "OK" : "missing")
        << ", obstacle sensor " << (data.obstacleSensorOk ? "OK" : "missing")
        << ", IR/thermal " << ((data.infraredSensorOk && data.thermalCameraOk) ? "OK" : "missing")
        << ", smoke/weather " << ((data.smokeSensorOk && data.weatherSensorOk) ? "OK" : "missing")
        << ", battery monitor " << (data.batteryMonitorOk ? "OK" : "missing") << ".\n";
    out << "- Required outputs: motor controller " << (data.motorControllerOk ? "OK" : "missing")
        << ", steering " << (data.steeringOk ? "OK" : "missing")
        << ", owner alert link " << (data.ownerAlertLinkOk ? "OK" : "missing")
        << ", communication link " << (data.communicationLinkOk ? "OK" : "missing")
        << ", speaker/light " << (data.speakerLightOk ? "OK" : "missing") << ".\n";
    out << "- Rule: every adapter must report freshness, faults, calibration, and fail closed to stop motion on stale or unsafe data.";
    return out.str();
}

std::string RealWorldDeploymentModule::solarBmsRequirements(const SensorData& data) const {
    std::ostringstream out;
    out << "Solar/BMS real-world requirements\n";
    out << "- Solar chain: panel " << (data.solarPanelConnected ? "connected" : "not connected")
        << ", controller " << (data.solarChargeControllerOk ? "OK" : "missing")
        << ", BMS telemetry " << (data.solarBmsTelemetryOk ? "OK" : "missing")
        << ", battery monitor " << (data.batteryMonitorOk ? "OK" : "missing") << ".\n";
    out << "- Must report battery voltage, percent, temperature, charge current, max charge voltage/current, controller state, fault codes, and disconnect state.\n";
    out << "- Must stop, taper, float, or disconnect charging during overcharge, overcurrent, high temperature, battery fault, controller fault, or full battery. Never bypass the controller/BMS.";
    return out.str();
}

std::string RealWorldDeploymentModule::ownerAuthenticationRequirements(const SensorData& data) const {
    return joinLines({
        "Owner authentication requirements",
        std::string("- Real owner authentication configured: ") + (data.realOwnerAuthenticationConfigured ? "yes" : "no") + ".",
        std::string("- Security keys configured: ") + (data.securityKeysConfigured ? "yes" : "no") + "; trusted controller present: " + (data.trustedControllerPresent ? "yes" : "no") + ".",
        "- Owner override and emergency shutdown should require real owner-only signals, but ethical constraints, safety stops, and privacy protections must never be bypassed."
    });
}

std::string RealWorldDeploymentModule::privacyEncryptionRequirements(const SensorData& data) const {
    return joinLines({
        "Private storage and encryption requirements",
        std::string("- Private storage configured: ") + (data.privateStorageConfigured ? "yes" : "no") + ".",
        std::string("- Encryption planned: ") + (data.privateStorageEncryptionPlanned ? "yes" : "no") + "; encryption active: " + (data.privateStorageEncryptionActive ? "yes" : "no") + ".",
        std::string("- Access audit OK: ") + (data.privateStorageAccessAuditOk ? "yes" : "no") + "; sensitive warnings acknowledged: " + (data.sensitiveFileWarningsAcknowledged ? "yes" : "no") + ".",
        "- Real deployment should use reviewed authenticated encryption, owner-held keys, least-privilege file access, and private report redaction before sharing anything outside owner/family or emergency responders."
    });
}

std::string RealWorldDeploymentModule::localKnowledgeRequirements(const SensorData& data) const {
    std::vector<std::string> gaps;
    if (!data.localKnowledgePackLoaded) {
        gaps.push_back("local knowledge pack");
    }
    if (data.localPlantNotes.empty() || data.localToxicLookalikes.empty()) {
        gaps.push_back("local plant and toxic-lookalike notes");
    }
    if (data.localWildlifeNotes.empty() || data.localInsectNotes.empty()) {
        gaps.push_back("local animal, insect, and arthropod notes");
    }
    if (data.localFishingRules.empty()) {
        gaps.push_back("local fishing rules and fish advisories");
    }
    if (data.localLandRules.empty() || data.localLegalNotes.empty()) {
        gaps.push_back("land access, collection, fire, water, and wildlife rules");
    }
    if (data.localMapNotes.empty() || data.emergencyContacts.empty()) {
        gaps.push_back("maps, evacuation notes, and emergency contacts");
    }
    if (gaps.empty()) {
        return "Local knowledge requirements: no obvious local-knowledge gaps from the current profile; recheck after moving regions or seasons.";
    }
    return "Local knowledge requirements: fill " + listItemsOrNone(gaps) + ".";
}

std::string RealWorldDeploymentModule::waterVerificationRequirements(const SensorData& data) const {
    return joinLines({
        "Water verification requirements",
        std::string("- Water filter available: ") + (data.waterFilterAvailable ? "yes" : "no") + "; clean containers: " + (data.cleanWaterContainersAvailable ? "yes" : "no") + ".",
        std::string("- Water quality verification available: ") + (data.waterQualityVerificationAvailable ? "yes" : "no") + "; local advisories checked: " + (data.localWaterAdvisoriesChecked ? "yes" : "no") + ".",
        "- The bot may teach filtering and disinfection, but real drinking decisions still require current advisories, clean handling, correct treatment, and avoiding chemical contamination, algae blooms, fuel/oil, sewage, mining runoff, or dead-animal contamination."
    });
}

std::string RealWorldDeploymentModule::mechanicalSafetyRequirements(const SensorData& data) const {
    return joinLines({
        "Mechanical safety requirements",
        std::string("- Mechanical inspection: ") + (data.mechanicalInspectionPassed ? "passed" : "missing") + "; weatherproofing: " + (data.weatherproofingOk ? "OK" : "missing") + ".",
        std::string("- Cable strain relief: ") + (data.cableStrainReliefOk ? "OK" : "missing") + "; battery fire safety: " + (data.batteryFireSafetyOk ? "OK" : "missing") + "; pinch-point guards: " + (data.pinchPointGuardsOk ? "OK" : "missing") + ".",
        "- Check stable center of gravity, speed limits, no sharp edges, protected wiring, fused circuits, ventilation, battery isolation, payload limits, traction, braking/stopping distance, and no exposed pinch/crush points."
    });
}

std::string RealWorldDeploymentModule::testingAndReviewRequirements(const SensorData& data) const {
    return joinLines({
        "Testing and review requirements",
        std::string("- Automated tests: ") + (data.automatedTestsPassed ? "passed" : "missing") + "; bench tests: " + (data.benchTestsPassed ? "passed" : "missing") + "; controlled outdoor tests: " + (data.controlledOutdoorTestsPassed ? "passed" : "missing") + ".",
        std::string("- Field risk assessment: ") + (data.fieldRiskAssessmentCompleted ? "done" : "missing") + "; qualified review: " + (data.qualifiedReviewCompleted ? "done" : "missing") + ".",
        "- Required progression: automated tests, desk tests, lifted-wheel motion tests, emergency-stop tests, low-speed owner-supervised walks, false-alarm review, solar/BMS charging test, rain/dust inspection, and qualified review."
    });
}

std::string RealWorldDeploymentModule::realWorldChecklist(const SensorData& data) const {
    return joinLines({
        deploymentGate(data),
        hardwareAdapterRequirements(data),
        solarBmsRequirements(data),
        ownerAuthenticationRequirements(data),
        privacyEncryptionRequirements(data),
        localKnowledgeRequirements(data),
        waterVerificationRequirements(data),
        mechanicalSafetyRequirements(data),
        testingAndReviewRequirements(data)
    });
}

std::string LocalKnowledgePackModule::buildKnowledgePack(const SensorData& data) const {
    std::ostringstream out;
    out << "CONSERVATION GUARDIAN LOCAL KNOWLEDGE PACK\n";
    out << "Keep private if it includes home/camp areas, routes, resources, hazards, contacts, or sensitive habitat locations.\n\n";
    out << "REGION\n";
    out << "Region name: " << data.regionName << "\n";
    out << "Home region: " << (data.homeRegion.empty() ? "not recorded" : data.homeRegion) << "\n";
    out << "Camp/base region: " << (data.campRegion.empty() ? "not recorded" : data.campRegion) << "\n";
    out << "Loaded flag: " << (data.localKnowledgePackLoaded ? "loaded" : "not loaded") << "\n\n";
    out << "FIELD KNOWLEDGE\n";
    out << "Local plant notes: " << listItemsOrNone(data.localPlantNotes) << "\n";
    out << "Toxic lookalikes: " << listItemsOrNone(data.localToxicLookalikes) << "\n";
    out << "Local wildlife notes: " << listItemsOrNone(data.localWildlifeNotes) << "\n";
    out << "Local insect/arthropod notes: " << listItemsOrNone(data.localInsectNotes) << "\n";
    out << "Fishing rules/advisories: " << listItemsOrNone(data.localFishingRules) << "\n";
    out << "Water advisories: " << listItemsOrNone(data.localWaterAdvisories) << "\n";
    out << "Weather risks: " << listItemsOrNone(data.localWeatherRisks) << "\n";
    out << "Land/legal rules: " << listItemsOrNone(data.localLandRules) << "\n";
    out << "Map notes: " << listItemsOrNone(data.localMapNotes) << "\n\n";
    out << knowledgeGaps(data) << "\n";
    out << usePolicy() << "\n";
    return out.str();
}

bool LocalKnowledgePackModule::saveKnowledgePack(const std::string& filePath, const SensorData& data, std::string& status) const {
    return writeTextFile(filePath, buildKnowledgePack(data), status, "Local knowledge pack");
}

bool LocalKnowledgePackModule::loadKnowledgePackText(const std::string& filePath, std::string& contents, std::string& status) const {
    return readTextFile(filePath, contents, status, "Local knowledge pack");
}

std::string LocalKnowledgePackModule::knowledgeGaps(const SensorData& data) const {
    std::vector<std::string> gaps;
    if (!data.localKnowledgePackLoaded) {
        gaps.push_back("mark local knowledge pack as loaded after owner review");
    }
    if (data.regionName == "unconfigured region" && data.homeRegion.empty() && data.campRegion.empty()) {
        gaps.push_back("specific region");
    }
    if (data.localPlantNotes.empty()) {
        gaps.push_back("local edible/unsafe plant notes");
    }
    if (data.localToxicLookalikes.empty()) {
        gaps.push_back("toxic lookalikes");
    }
    if (data.localWildlifeNotes.empty()) {
        gaps.push_back("local wildlife behavior and protected species");
    }
    if (data.localFishingRules.empty()) {
        gaps.push_back("current fishing rules and fish-consumption advisories");
    }
    if (data.localWaterAdvisories.empty()) {
        gaps.push_back("water advisories and purification concerns");
    }
    if (data.localWeatherRisks.empty()) {
        gaps.push_back("seasonal weather, fire, flood, heat, cold, and smoke risks");
    }
    if (data.localLandRules.empty()) {
        gaps.push_back("land ownership, access, collection, fire, water, and wildlife rules");
    }
    if (data.emergencyContacts.empty()) {
        gaps.push_back("local emergency contacts");
    }

    if (gaps.empty()) {
        return "Local knowledge gaps: no obvious gaps from current data. Recheck when season, region, rules, or advisories change.";
    }
    return "Local knowledge gaps to fill: " + listItemsOrNone(gaps) + ".";
}

std::string LocalKnowledgePackModule::usePolicy() const {
    return "Local knowledge policy: use trusted local sources, update after rule/advisory changes, keep sensitive locations private, and never override current safety sensors or emergency instructions.";
}

std::string MapGeofenceModule::buildMapPlan(const SensorData& data) const {
    std::ostringstream out;
    out << "CONSERVATION GUARDIAN MAP AND GEOFENCE PLAN\n";
    out << "Keep private if it names home, camp, water, routes, hazards, private land, or sensitive habitat.\n\n";
    out << "LOCATION CONTEXT\n";
    out << "Current location: " << (data.locationKnown ? data.locationDescription : "unknown") << "\n";
    out << "Terrain: " << toString(data.terrain) << "\n";
    out << "Geofence configured: " << (data.geofenceConfigured ? "yes" : "no") << "\n\n";
    out << "MAP LAYERS\n";
    out << "Safe zones: " << listItemsOrNone(data.safeZoneNames) << "\n";
    out << "No-go zones: " << listItemsOrNone(data.noGoZoneNames) << "\n";
    out << "Known water sources: " << listItemsOrNone(data.knownWaterSources) << "\n";
    out << "Known shelter sites: " << listItemsOrNone(data.knownShelterSites) << "\n";
    out << "Evacuation routes: " << listItemsOrNone(data.evacuationRoutes) << "\n";
    out << "Sensitive habitats: " << listItemsOrNone(data.sensitiveHabitats) << "\n";
    out << "Private/restricted boundaries: " << listItemsOrNone(data.privateLandBoundaries) << "\n";
    out << "Road/cliff/water hazards: " << listItemsOrNone(data.roadAndCliffHazards) << "\n";
    out << "Local map notes: " << listItemsOrNone(data.localMapNotes) << "\n\n";
    out << routeSafetyDecision(data) << "\n";
    out << geofencePolicy() << "\n";
    return out.str();
}

bool MapGeofenceModule::saveMapPlan(const std::string& filePath, const SensorData& data, std::string& status) const {
    return writeTextFile(filePath, buildMapPlan(data), status, "Map/geofence plan");
}

bool MapGeofenceModule::loadMapPlanText(const std::string& filePath, std::string& contents, std::string& status) const {
    return readTextFile(filePath, contents, status, "Map/geofence plan");
}

std::string MapGeofenceModule::routeSafetyDecision(const SensorData& data) const {
    std::vector<std::string> blockers;
    if (!data.locationKnown || !data.gpsOk) {
        blockers.push_back("location/GPS not verified");
    }
    if (!data.geofenceConfigured) {
        blockers.push_back("geofence/no-go zones not configured");
    }
    if (data.noGoZoneNames.empty()) {
        blockers.push_back("no-go zones not listed");
    }
    if (data.safeZoneNames.empty()) {
        blockers.push_back("safe zones not listed");
    }
    if (data.evacuationRoutes.empty()) {
        blockers.push_back("evacuation routes not listed");
    }
    if (data.steepOrSlipperyTerrain || data.floodOrRockfallRisk || data.smokeDetected || data.fireDetected) {
        blockers.push_back("current terrain/fire/weather hazard");
    }

    if (blockers.empty()) {
        return "Map/geofence decision: route planning may be used cautiously with owner supervision, current sensor checks, and low-impact travel.";
    }
    return "Map/geofence decision: advisory only until resolved: " + listItemsOrNone(blockers) + ".";
}

std::string MapGeofenceModule::geofencePolicy() const {
    return "Geofence policy: no-go zones include roads, cliffs, unsafe water edges, private/restricted land, cultural sites, nests/dens/breeding grounds, fragile habitat, fire/smoke areas, and any owner-marked danger area.";
}

std::string CalibrationModule::calibrationReport(const SensorData& data) const {
    std::vector<std::string> lines{"Calibration report"};
    const auto add = [&lines](const std::string& name, bool ok, const std::string& note) {
        lines.push_back("- " + name + ": " + (ok ? "CALIBRATED/TESTED" : "NEEDS CALIBRATION") + " - " + note);
    };

    add("GPS", data.gpsCalibrated, "verify known landmarks and emergency location format.");
    add("IMU/tilt", data.imuCalibrated, "verify level, tilt, fall, and stuck-position detection.");
    add("Compass/heading", data.compassCalibrated, "verify away from magnets, motors, and metal structures.");
    add("Obstacle sensor", data.obstacleSensorCalibrated, "verify stop distance at low speed with soft test obstacles.");
    add("Battery monitor", data.batteryMonitorCalibrated, "compare voltage/percentage to a trusted meter and battery label.");
    add("Camera", data.cameraCalibrated, "verify framing while respecting privacy.");
    add("Thermal camera", data.thermalCameraCalibrated, "verify heat-signature education without privacy misuse.");
    add("Infrared/IR sensor", data.infraredSensorCalibrated, "verify low-light motion or heat-signature cues against safe references without privacy misuse.");
    add("Smoke/fire sensor", data.smokeSensorCalibrated, "verify by manufacturer-safe test method only.");
    add("Weather sensor", data.weatherSensorCalibrated, "compare temperature, humidity, and wind readings against trusted references.");
    add("Owner alert test", data.ownerAlertTestPassed, "verify silent private alert reaches owner/family.");
    add("Emergency stop test", data.emergencyStopTestPassed, "verify physical stop cuts motion safely.");
    add("Motor stop test", data.motorStopTestPassed, "verify stop on command timeout, obstacle, low battery, tilt, and owner stop.");
    lines.push_back(calibrationDecision(data));
    return joinVectorLines(lines);
}

std::string CalibrationModule::sensorCalibrationChecklist() const {
    return joinLines({
        "Sensor calibration checklist",
        "Use known references: marked location, known level surface, measured distance, trusted thermometer/hygrometer, battery meter, controlled lighting, and safe warm/cool references for thermal or infrared sensors.",
        "Record date, place, reference tool, result, and whether the reading is good enough for safety use.",
        "If a sensor drifts, disagrees, or becomes stale, downgrade to advisory mode and stop motion if it affects navigation or safety."
    });
}

std::string CalibrationModule::actuatorCalibrationChecklist() const {
    return joinLines({
        "Actuator calibration checklist",
        "Test with wheels lifted first, then low speed in a clear area with a human spotter and emergency stop in hand.",
        "Confirm speed limits, steering direction, braking/stop distance, command timeout, obstacle stop, low-battery stop, and tilt/fall stop.",
        "Never calibrate near stairs, roads, water edges, children, pets, wildlife, fragile habitat, or bystanders."
    });
}

std::string CalibrationModule::calibrationDecision(const SensorData& data) const {
    const bool safetyCritical = data.gpsCalibrated
        && data.imuCalibrated
        && data.obstacleSensorCalibrated
        && data.batteryMonitorCalibrated
        && data.ownerAlertTestPassed
        && data.emergencyStopTestPassed
        && data.motorStopTestPassed;
    if (safetyCritical) {
        return "Calibration decision: safety-critical calibration is marked complete in this simulated status; continue supervised bench/outdoor tests.";
    }
    return "Calibration decision: not ready for real movement. Keep demo/advisory mode until GPS, IMU, obstacle, battery, owner alert, emergency stop, and motor stop tests pass.";
}

std::string HardwareAdapterCatalogModule::adapterOverview() const {
    return joinLines({
        "Hardware adapter interface plan",
        "Each real part should live behind a small adapter with readStatus(), selfTest(), lastUpdateAge(), and safeShutdown() or stop() where relevant.",
        "Adapters should report OK/NEEDS_CHECK/FAILED, never hide stale data, and never command movement directly without the safety controller."
    });
}

std::string HardwareAdapterCatalogModule::sensorAdapters() const {
    return joinLines({
        "Sensor adapters to create",
        "- GpsAdapter: location, accuracy, timestamp, emergency location string.",
        "- ImuAdapter: tilt, fall/stuck risk, heading if available.",
        "- CompassGeofenceAdapter: heading confidence, safe zones, no-go zones, private boundaries, and habitat buffers.",
        "- BatteryMonitorAdapter: voltage, percent, current, temperature, low/critical flags.",
        "- SolarChargeAdapter: panel/controller state, battery charging status, charge faults, and load disconnect state.",
        "- CameraAdapter, ThermalAdapter, and InfraredAdapter: health/framing/motion or heat-signature cues by default; privacy-aware image or sensing use requires owner consent.",
        "- SmokeWeatherAdapter: smoke/fire flag, temperature, humidity, wind trend.",
        "- ObstacleAdapter: distance zones, blocked path, sensor age.",
        "- PayloadAdapter: load weight, shifting load, overload, and stability cue.",
        "- MedicalRequestAdapter: non-invasive owner/family help button, voice request, optional vitals input, and consent status.",
        "- WaterFilterStorageAdapter and FoodStorageAdapter: readiness and safety flags for filter/container/pantry support; never certify unsafe water or food from weak evidence.",
        "- CommunicationsAdapter: private owner device, phone/radio link quality, delivery status, and offline fallback."
    });
}

std::string HardwareAdapterCatalogModule::actuatorAdapters() const {
    return joinLines({
        "Actuator adapters to create",
        "- MotorControllerAdapter: enable, speed limit, stop, command timeout, fault state.",
        "- SteeringAdapter: bounded steering target and neutral/stop state.",
        "- OwnerAlertAdapter: silent paired owner/family alerts with delivery status and privacy lock.",
        "- LightSpeakerAdapter: low-intensity signaling, owner alert, gentle wildlife deterrence only when ethical.",
        "- EmergencyStopAdapter: physical stop status, last test time, and hard stop signal.",
        "- CommsAdapter: private owner alert, emergency message draft, link quality, offline fallback."
    });
}

std::string HardwareAdapterCatalogModule::adapterSafetyContract() const {
    return "Adapter safety contract: missing, stale, contradictory, or failed hardware data must produce STOP_MOTION, preserve private alerts, log the issue, and wait for verified owner action.";
}

std::string VoicePhoneInterfaceModule::interfacePlan(const SensorData& data) const {
    std::ostringstream out;
    out << "Voice and phone interface plan\n";
    out << "Voice interface configured: " << (data.voiceInterfaceConfigured ? "yes" : "no") << ". ";
    out << "Phone/private alert configured: " << (data.phoneAlertConfigured ? "yes" : "no") << ". ";
    out << "Offline voice commands cached: " << (data.offlineVoiceCommandsCached ? "yes" : "no") << ".\n";
    out << "Use voice for natural questions and phone/pairing for private alerts, reports, owner profile review, and authentication prompts.";
    return out.str();
}

std::string VoicePhoneInterfaceModule::commandSafetyRules() const {
    return joinLines({
        "Voice/phone command safety rules",
        "Voice alone should not unlock emergency shutdown, owner override, private reports, or authorized machine-stop controls.",
        "Require owner/family presence plus a stronger factor such as PIN, paired device, hardware key, or secure local token.",
        "In noisy, emergency, or uncertain conditions, repeat back the safe interpretation and choose stop/retreat/advisory mode."
    });
}

std::string VoicePhoneInterfaceModule::privateAlertPlan() const {
    return "Private alert plan: send short silent alerts only to owner/family devices; include risk, recommended action, confidence, and whether a report is available for logging.";
}

std::string VoicePhoneInterfaceModule::offlineFallbackPlan() const {
    return "Offline fallback: cache core commands, maps, owner profile, local knowledge, and emergency message templates locally; if the phone link fails, keep lights/sound signaling and written reports available.";
}

std::string HardwareDriverBridgeModule::driverBridgeOverview(const SensorData& data) const {
    std::ostringstream out;
    out << "Hardware driver bridge overview\n";
    out << "Mode: " << (data.realHardwareMode ? "real hardware requested" : "demo/advisory mode") << ".\n";
    out << "Drivers installed: " << (data.hardwareDriversInstalled ? "yes" : "no") << ". ";
    out << "Sensor bridge online: " << (data.sensorDriverBridgeOnline ? "yes" : "no") << ". ";
    out << "Actuator bridge online: " << (data.actuatorDriverBridgeOnline ? "yes" : "no") << ". ";
    out << "Motor output armed: " << (data.motorOutputArmed ? "yes" : "no") << ".\n";
    out << "Connected sensor drivers: " << listItemsOrNone(data.connectedSensorDrivers) << "\n";
    out << "Connected actuator drivers: " << listItemsOrNone(data.connectedActuatorDrivers) << "\n";
    out << driverFaultResponse(data);
    return out.str();
}

std::string HardwareDriverBridgeModule::sensorDriverContract() const {
    return joinLines({
        "Sensor driver contract",
        "- Drivers may report readings, health, timestamp freshness, confidence, and calibration status.",
        "- Drivers must never decide to move the bot directly; they only feed the guardian brain.",
        "- Missing, stale, conflicting, or low-confidence readings must be marked as uncertain.",
        "- Camera, thermal, and infrared data must follow privacy rules and owner/family consent.",
        "- Fire, smoke, obstacle, owner/family position, GPS/geofence, IMU/tilt, battery, solar charging faults, communications, owner alerts, and emergency-stop signals are safety-critical."
    });
}

std::string HardwareDriverBridgeModule::actuatorDriverContract() const {
    return joinLines({
        "Actuator driver contract",
        "- Motors, steering, lights, speaker, and alerts accept only bounded, mission-safe commands.",
        "- Movement commands must include speed limits, stop-on-fault behavior, obstacle checks, and geofence checks.",
        "- Default output is stop/off/safe when commands are stale, authentication fails, battery is unsafe, or sensors disagree.",
        "- Physical outputs may not be used for harm, intimidation, pursuit, ramming, trapping, or coercion.",
        "- Emergency stop and safe stop on fault override every nonessential output."
    });
}

std::string HardwareDriverBridgeModule::safeOutputGate(const SensorData& data) const {
    const bool coreReady = data.realHardwareMode
        && data.hardwareInterfaceConnected
        && data.hardwareDriversInstalled
        && data.sensorDriverBridgeOnline
        && data.actuatorDriverBridgeOnline
        && data.emergencyStopCircuitOk
        && data.safeStopOnFaultOk
        && data.ownerAlertLinkOk
        && data.communicationLinkOk
        && data.batteryMonitorOk
        && data.obstacleSensorOk
        && data.gpsOk
        && data.imuOk
        && data.steeringOk
        && data.geofenceConfigured
        && !data.driverBridgeFaultDetected;
    const bool calibrationReady = data.gpsCalibrated
        && data.imuCalibrated
        && data.compassCalibrated
        && data.obstacleSensorCalibrated
        && data.batteryMonitorCalibrated
        && data.ownerAlertTestPassed
        && data.emergencyStopTestPassed
        && data.motorStopTestPassed;

    if (!data.realHardwareMode) {
        return "Safe output gate: demo/advisory mode. Keep motor output disabled and use logs, reports, and simulated commands only.";
    }
    if (!coreReady || !calibrationReady) {
        return "Safe output gate: motor output must remain disarmed. Real movement requires drivers, calibrated safety sensors, communication, geofence, owner alerts, emergency stop, safe stop on fault, and no driver faults.";
    }
    if (!data.motorOutputArmed) {
        return "Safe output gate: ready for supervised bench/outdoor arming, but output is currently disarmed. This is the preferred safe default.";
    }
    return "Safe output gate: limited supervised movement may run only inside geofence, at low speed, with owner present, emergency stop reachable, and automatic stop on any fault.";
}

std::string HardwareDriverBridgeModule::driverFaultResponse(const SensorData& data) const {
    if (!data.driverBridgeFaultDetected && data.driverFaultNotes.empty()) {
        return "Driver fault response: no driver bridge faults are currently listed.";
    }

    std::ostringstream out;
    out << "Driver fault response: stop motion, hold position if safe, alert owner/family privately, write an audit entry, and require inspection before re-arming.\n";
    out << "Fault notes: " << listItemsOrNone(data.driverFaultNotes);
    return out.str();
}

HardwareSensorFrame HardwareStubLayerModule::buildSensorFrame(const SensorData& data) const {
    HardwareSensorFrame frame;
    frame.source = data.simulatedHardwareMode ? "simulated hardware stub" : "real adapter placeholder";
    frame.fresh = data.simulatedSensorFrameFresh;
    frame.gpsLock = data.simulatedGpsLock && data.gpsOk;
    frame.obstacleAhead = data.simulatedObstacleAhead || data.unstableTerrainDetected || data.steepOrSlipperyTerrain;
    frame.thermalCameraActive = data.thermalCameraOk;
    frame.infraredSensorActive = data.infraredSensorOk;
    frame.thermalHotspotDetected = data.thermalHotspotDetected || data.fireDetected || data.smokeDetected;
    frame.infraredMotionDetected = data.infraredMotionDetected || data.infraredHeatSignatureDetected;
    frame.emergencyStopPressed = data.simulatedEmergencyStopPressed || data.shutdownCommand;
    frame.commandTimedOut = data.simulatedCommandTimeout;
    frame.sensorFault = data.simulatedSensorFault || data.driverBridgeFaultDetected;
    frame.batteryPercent = data.batteryPercent;
    frame.botPosition = data.botPosition;
    frame.ownerPosition = data.ownerPosition;
    frame.events = data.simulatedHardwareEvents;

    if (!frame.fresh) {
        frame.events.push_back("sensor frame is stale");
    }
    if (!frame.gpsLock) {
        frame.events.push_back("GPS lock unavailable or unverified");
    }
    if (frame.obstacleAhead) {
        frame.events.push_back("obstacle or unstable terrain ahead");
    }
    if (frame.thermalHotspotDetected) {
        frame.events.push_back("thermal hotspot or heat-risk cue detected");
    }
    if (frame.infraredMotionDetected) {
        frame.events.push_back("infrared motion or heat-signature cue detected");
    }
    if (frame.emergencyStopPressed) {
        frame.events.push_back("emergency stop signal active");
    }
    if (frame.commandTimedOut) {
        frame.events.push_back("hardware command timeout");
    }
    if (frame.sensorFault) {
        frame.events.push_back("sensor/driver fault");
    }
    if (data.simulatedActuatorFault) {
        frame.events.push_back("actuator fault");
    }
    return frame;
}

HardwareOutputCommand HardwareStubLayerModule::plannedOutputForState(BotState state, const SensorData& data) const {
    const HardwareSensorFrame frame = buildSensorFrame(data);
    HardwareOutputCommand command;
    command.target = "simulated actuator layer";

    const bool hardStop = frame.emergencyStopPressed
        || frame.commandTimedOut
        || frame.sensorFault
        || data.simulatedActuatorFault
        || data.driverBridgeFaultDetected
        || !data.driverFaultNotes.empty()
        || !frame.fresh;
    const bool readyForMotion = data.realHardwareMode
        && data.hardwareDriversInstalled
        && data.sensorDriverBridgeOnline
        && data.actuatorDriverBridgeOnline
        && data.hardwareInterfaceConnected
        && data.motorOutputArmed
        && data.emergencyStopCircuitOk
        && data.safeStopOnFaultOk
        && data.obstacleSensorOk
        && data.imuOk
        && data.steeringOk
        && data.batteryMonitorOk
        && data.ownerAlertLinkOk
        && data.communicationLinkOk
        && data.geofenceConfigured
        && data.ownerAuthenticated
        && frame.gpsLock
        && !frame.obstacleAhead
        && !hardStop;

    if (hardStop) {
        command.allowMotion = false;
        command.stopMotion = true;
        command.speedLimitMps = 0.0;
        command.rationale = "STOP_MOTION: emergency stop, timeout, stale data, sensor fault, actuator fault, or driver fault requires safe output.";
        command.notes = frame.events;
        return command;
    }
    if (!data.realHardwareMode || data.simulatedHardwareMode) {
        command.allowMotion = false;
        command.stopMotion = true;
        command.speedLimitMps = 0.0;
        command.rationale = "STOP_MOTION: simulated/advisory layer only. The brain may plan movement, but fake hardware must not move real motors.";
        command.notes = {"Use this output to test logic before connecting real hardware."};
        return command;
    }
    if (!readyForMotion) {
        command.allowMotion = false;
        command.stopMotion = true;
        command.speedLimitMps = 0.0;
        command.rationale = "STOP_MOTION: real adapter prerequisites are incomplete. Keep motors disarmed until authentication, geofence, emergency stop, drivers, sensors, and communication are verified.";
        command.notes = frame.events;
        if (!data.motorOutputArmed) {
            command.notes.push_back("motor output is not armed");
        }
        return command;
    }

    command.allowMotion = true;
    command.stopMotion = false;
    if (state == BotState::Retreat || state == BotState::FireEscape) {
        command.speedLimitMps = 0.55;
        command.rationale = "LIMITED_MOTION: supervised retreat/fire-escape movement inside geofence with stop-on-fault active.";
    } else if (state == BotState::EscortHuman || state == BotState::Idle || state == BotState::NightPatrol) {
        command.speedLimitMps = 0.30;
        command.rationale = "LIMITED_MOTION: slow owner-following or repositioning movement inside geofence.";
    } else {
        command.allowMotion = false;
        command.stopMotion = true;
        command.speedLimitMps = 0.0;
        command.rationale = "STOP_MOTION: current state should stay advisory or stationary unless owner-supervised route movement is explicitly safe.";
    }
    command.notes = {"Automatic stop remains active for obstacle, timeout, emergency stop, command loss, low battery, or geofence violation."};
    return command;
}

std::string HardwareStubLayerModule::sensorFrameReport(const HardwareSensorFrame& frame) const {
    std::ostringstream out;
    out << "Simulated sensor frame\n";
    out << "Source: " << frame.source << "\n";
    out << "Fresh: " << (frame.fresh ? "yes" : "no") << ". ";
    out << "GPS lock: " << (frame.gpsLock ? "yes" : "no") << ". ";
    out << "Obstacle ahead: " << (frame.obstacleAhead ? "yes" : "no") << ". ";
    out << "Thermal active: " << (frame.thermalCameraActive ? "yes" : "no") << ". ";
    out << "IR active: " << (frame.infraredSensorActive ? "yes" : "no") << ".\n";
    out << "Thermal hotspot: " << (frame.thermalHotspotDetected ? "yes" : "no") << ". ";
    out << "IR motion/heat cue: " << (frame.infraredMotionDetected ? "yes" : "no") << ". ";
    out << "Emergency stop: " << (frame.emergencyStopPressed ? "active" : "not active") << ".\n";
    out << "Command timeout: " << (frame.commandTimedOut ? "yes" : "no") << ". ";
    out << "Sensor fault: " << (frame.sensorFault ? "yes" : "no") << ". ";
    out << "Battery: " << frame.batteryPercent << "%.\n";
    out << "Bot position: " << pointText(frame.botPosition) << ". Owner position: " << pointText(frame.ownerPosition) << ".\n";
    out << "Events: " << listItemsOrNone(frame.events);
    return out.str();
}

std::string HardwareStubLayerModule::outputCommandReport(const HardwareOutputCommand& command) const {
    std::ostringstream out;
    out << "Simulated output command\n";
    out << "Target: " << command.target << "\n";
    out << "Allow motion: " << (command.allowMotion ? "yes" : "no") << ". ";
    out << "Stop motion: " << (command.stopMotion ? "yes" : "no") << ". ";
    out << "Speed limit: " << command.speedLimitMps << " m/s.\n";
    out << "Rationale: " << command.rationale << "\n";
    out << "Notes: " << listItemsOrNone(command.notes);
    return out.str();
}

std::string HardwareStubLayerModule::stubSafetyContract() const {
    return joinLines({
        "Hardware stub safety contract",
        "- Fake sensors may test guardian logic but must never claim real-world certainty.",
        "- Fake actuator commands default to STOP_MOTION and cannot move real motors.",
        "- Real adapters must match the same input/output shape: fresh sensor frame in, bounded output command out.",
        "- Any stale frame, timeout, obstacle, emergency stop, sensor fault, actuator fault, or driver fault forces STOP_MOTION.",
        "- The stub layer exists so real hardware can be added without rewriting guardian ethics, reporting, navigation, or medical logic."
    });
}

std::string HardwareStubLayerModule::realAdapterSwapPlan() const {
    return joinLines({
        "Real adapter swap plan",
        "1. Keep the guardian brain unchanged.",
        "2. Replace fake frame values with readings from GPS, IMU/compass, geofence/map, obstacle, payload, battery, solar charge, smoke/weather, camera, thermal, infrared/IR, water/filter, food storage, communications, medical request, and emergency-stop adapters.",
        "3. Replace fake output reporting with owner-alert, motor, steering, light/speaker, and phone/radio adapters that accept only HardwareOutputCommand-style safe commands.",
        "4. Run bench tests with motors disconnected, then controlled walk tests, then field tests.",
        "5. If any adapter cannot prove freshness, calibration, and stop-on-fault behavior, keep real movement disabled."
    });
}

HardwareDriverStatus GpsDriverInterface::fakeStatus(const SensorData& data) const {
    HardwareDriverStatus status;
    status.driverName = "GpsDriverInterface";
    status.mode = data.simulatedHardwareMode ? "fake GPS driver" : "real GPS driver placeholder";
    status.installed = data.hardwareDriversInstalled;
    status.online = data.sensorDriverBridgeOnline && data.gpsOk;
    status.fresh = data.simulatedSensorFrameFresh;
    status.calibrated = data.gpsCalibrated;
    status.fault = data.simulatedSensorFault || !data.simulatedGpsLock || data.driverBridgeFaultDetected;
    status.detail = data.locationKnown ? data.locationDescription : "location unknown";
    return status;
}

std::string GpsDriverInterface::fakeReading(const SensorData& data) const {
    std::ostringstream out;
    out << "Fake GPS driver reading: lock " << ((data.simulatedGpsLock && data.gpsOk) ? "yes" : "no")
        << ", bot " << pointText(data.botPosition)
        << ", owner " << pointText(data.ownerPosition)
        << ", location " << (data.locationKnown ? data.locationDescription : "unknown") << ".";
    return out.str();
}

std::string GpsDriverInterface::realDriverNotes() const {
    return "GpsDriverInterface real notes: report latitude/longitude or local map coordinates, accuracy, fix age, timestamp, lock quality, and emergency-readable location; never command movement directly.";
}

HardwareDriverStatus BatteryDriverInterface::fakeStatus(const SensorData& data) const {
    HardwareDriverStatus status;
    status.driverName = "BatteryDriverInterface";
    status.mode = data.simulatedHardwareMode ? "fake battery driver" : "real battery driver placeholder";
    status.installed = data.hardwareDriversInstalled;
    status.online = data.sensorDriverBridgeOnline && data.batteryMonitorOk;
    status.fresh = data.simulatedSensorFrameFresh;
    status.calibrated = data.batteryMonitorCalibrated;
    status.fault = data.simulatedSensorFault || data.batteryPercent <= 5.0 || data.driverBridgeFaultDetected;
    std::ostringstream detail;
    detail << "battery " << data.batteryPercent << "%, capacity " << data.batteryCapacityWh
        << " Wh, load " << data.electricalLoadWatts << " W";
    status.detail = detail.str();
    return status;
}

std::string BatteryDriverInterface::fakeReading(const SensorData& data) const {
    std::ostringstream out;
    out << "Fake battery driver reading: " << data.batteryPercent << "%, "
        << data.batteryCapacityWh << " Wh capacity, estimated load "
        << data.electricalLoadWatts << " W.";
    return out.str();
}

std::string BatteryDriverInterface::realDriverNotes() const {
    return "BatteryDriverInterface real notes: report voltage, current, temperature, percent estimate, charging state, low/critical thresholds, and freshness; unsafe battery readings force stop-motion and owner alert.";
}

HardwareDriverStatus ObstacleDriverInterface::fakeStatus(const SensorData& data) const {
    HardwareDriverStatus status;
    status.driverName = "ObstacleDriverInterface";
    status.mode = data.simulatedHardwareMode ? "fake obstacle driver" : "real obstacle driver placeholder";
    status.installed = data.hardwareDriversInstalled;
    status.online = data.sensorDriverBridgeOnline && data.obstacleSensorOk;
    status.fresh = data.simulatedSensorFrameFresh;
    status.calibrated = data.obstacleSensorCalibrated;
    status.fault = data.simulatedSensorFault || data.driverBridgeFaultDetected;
    status.detail = (data.simulatedObstacleAhead || data.unstableTerrainDetected || data.steepOrSlipperyTerrain)
        ? "blocked/unstable path reported"
        : "path clear in fake reading";
    return status;
}

std::string ObstacleDriverInterface::fakeReading(const SensorData& data) const {
    if (data.simulatedObstacleAhead || data.unstableTerrainDetected || data.steepOrSlipperyTerrain) {
        return "Fake obstacle driver reading: obstacle or unstable terrain ahead; output must stop or choose a safer route.";
    }
    return "Fake obstacle driver reading: no obstacle injected; continue to rely on geofence, slow speed, and stop-on-fault.";
}

std::string ObstacleDriverInterface::realDriverNotes() const {
    return "ObstacleDriverInterface real notes: report near/mid/far blocked zones, cliff/drop risk if available, confidence, timestamp, and sensor health; it must fail closed to stop-motion.";
}

HardwareDriverStatus EmergencyStopDriverInterface::fakeStatus(const SensorData& data) const {
    HardwareDriverStatus status;
    status.driverName = "EmergencyStopDriverInterface";
    status.mode = data.simulatedHardwareMode ? "fake emergency-stop driver" : "real emergency-stop driver placeholder";
    status.installed = data.hardwareDriversInstalled;
    status.online = data.emergencyStopCircuitOk;
    status.fresh = true;
    status.calibrated = data.emergencyStopTestPassed;
    status.fault = !data.emergencyStopCircuitOk || data.driverBridgeFaultDetected;
    status.detail = (data.simulatedEmergencyStopPressed || data.shutdownCommand)
        ? "stop signal active"
        : "stop signal not active";
    return status;
}

std::string EmergencyStopDriverInterface::fakeReading(const SensorData& data) const {
    return std::string("Fake emergency-stop driver reading: ")
        + ((data.simulatedEmergencyStopPressed || data.shutdownCommand) ? "STOP active." : "stop not active.");
}

std::string EmergencyStopDriverInterface::realDriverNotes() const {
    return "EmergencyStopDriverInterface real notes: physical stop must be hard-wired, reachable, tested, debounced, and independent enough to stop motion even if the brain software misbehaves.";
}

HardwareDriverStatus InfraredThermalDriverInterface::fakeStatus(const SensorData& data) const {
    HardwareDriverStatus status;
    status.driverName = "InfraredThermalDriverInterface";
    status.mode = data.simulatedHardwareMode ? "fake IR/thermal driver" : "real IR/thermal driver placeholder";
    status.installed = data.hardwareDriversInstalled;
    status.online = data.sensorDriverBridgeOnline && (data.thermalCameraOk || data.infraredSensorOk);
    status.fresh = data.simulatedSensorFrameFresh;
    status.calibrated = data.thermalCameraCalibrated || data.infraredSensorCalibrated;
    status.fault = data.simulatedSensorFault || data.driverBridgeFaultDetected;
    std::ostringstream detail;
    detail << "thermal " << (data.thermalCameraOk ? "OK" : "not verified")
        << ", infrared " << (data.infraredSensorOk ? "OK" : "not verified")
        << ", heat cues "
        << ((data.thermalSignatureDetected || data.thermalHotspotDetected || data.infraredHeatSignatureDetected) ? "present" : "none")
        << ", IR motion " << (data.infraredMotionDetected ? "present" : "none");
    status.detail = detail.str();
    return status;
}

std::string InfraredThermalDriverInterface::fakeReading(const SensorData& data) const {
    std::ostringstream out;
    out << "Fake IR/thermal driver reading: thermal camera "
        << (data.thermalCameraOk ? "OK" : "not verified")
        << ", infrared sensor " << (data.infraredSensorOk ? "OK" : "not verified")
        << ", thermal signature " << (data.thermalSignatureDetected ? "detected" : "not detected")
        << ", thermal hotspot " << (data.thermalHotspotDetected ? "detected" : "not detected")
        << ", infrared motion " << (data.infraredMotionDetected ? "detected" : "not detected")
        << ", infrared heat signature " << (data.infraredHeatSignatureDetected ? "detected" : "not detected")
        << ". Use only for safety awareness, never stalking, privacy invasion, or harassment.";
    return out.str();
}

std::string InfraredThermalDriverInterface::realDriverNotes() const {
    return "InfraredThermalDriverInterface real notes: report thermal/IR sensor health, calibration, field of view, timestamp freshness, confidence, saturated readings, heat/motion cues, and privacy mode; stale or uncertain readings stay advisory and cannot trigger pursuit.";
}

HardwareDriverStatus ImuCompassDriverInterface::fakeStatus(const SensorData& data) const {
    HardwareDriverStatus status;
    status.driverName = "ImuCompassDriverInterface";
    status.mode = data.simulatedHardwareMode ? "fake IMU/compass driver" : "real IMU/compass driver placeholder";
    status.installed = data.hardwareDriversInstalled;
    status.online = data.sensorDriverBridgeOnline && data.imuOk;
    status.fresh = data.simulatedSensorFrameFresh;
    status.calibrated = data.imuCalibrated && data.compassCalibrated;
    status.fault = data.simulatedSensorFault || data.driverBridgeFaultDetected;
    std::ostringstream detail;
    detail << "owner facing " << pointText(data.ownerFacingDirection)
        << ", unstable terrain " << (data.unstableTerrainDetected ? "yes" : "no")
        << ", steep/slippery " << (data.steepOrSlipperyTerrain ? "yes" : "no");
    status.detail = detail.str();
    return status;
}

std::string ImuCompassDriverInterface::fakeReading(const SensorData& data) const {
    std::ostringstream out;
    out << "Fake IMU/compass driver reading: IMU " << (data.imuOk ? "OK" : "not verified")
        << ", IMU calibrated " << (data.imuCalibrated ? "yes" : "not yet")
        << ", compass calibrated " << (data.compassCalibrated ? "yes" : "not yet")
        << ", owner-facing vector " << pointText(data.ownerFacingDirection)
        << ", stability cue " << ((data.unstableTerrainDetected || data.steepOrSlipperyTerrain) ? "caution" : "normal") << ".";
    return out.str();
}

std::string ImuCompassDriverInterface::realDriverNotes() const {
    return "ImuCompassDriverInterface real notes: report tilt, roll/pitch/yaw if available, heading confidence, calibration age, stuck/fall clues, and timestamp freshness; uncertain orientation must slow or stop movement.";
}

HardwareDriverStatus CameraDriverInterface::fakeStatus(const SensorData& data) const {
    HardwareDriverStatus status;
    status.driverName = "CameraDriverInterface";
    status.mode = data.simulatedHardwareMode ? "fake camera driver" : "real camera driver placeholder";
    status.installed = data.hardwareDriversInstalled;
    status.online = data.sensorDriverBridgeOnline && data.cameraOk;
    status.fresh = data.simulatedSensorFrameFresh;
    status.calibrated = data.cameraCalibrated;
    status.fault = data.simulatedSensorFault || data.driverBridgeFaultDetected;
    status.detail = data.visibilityReduced ? "visibility reduced; advisory framing only" : "visual cue stream placeholder";
    return status;
}

std::string CameraDriverInterface::fakeReading(const SensorData& data) const {
    std::ostringstream out;
    out << "Fake camera driver reading: camera " << (data.cameraOk ? "OK" : "not verified")
        << ", calibrated " << (data.cameraCalibrated ? "yes" : "not yet")
        << ", visibility " << (data.visibilityReduced ? "reduced" : "normal")
        << ", privacy mode: do not identify outsiders or share imagery without owner/family safety need.";
    return out.str();
}

std::string CameraDriverInterface::realDriverNotes() const {
    return "CameraDriverInterface real notes: report health, exposure/framing, obstacle/terrain cues, privacy mode, timestamp freshness, and confidence; it should support safety awareness without face tracking, harassment, or hidden surveillance.";
}

HardwareDriverStatus SmokeWeatherDriverInterface::fakeStatus(const SensorData& data) const {
    HardwareDriverStatus status;
    status.driverName = "SmokeWeatherDriverInterface";
    status.mode = data.simulatedHardwareMode ? "fake smoke/weather driver" : "real smoke/weather driver placeholder";
    status.installed = data.hardwareDriversInstalled;
    status.online = data.sensorDriverBridgeOnline && (data.smokeSensorOk || data.weatherSensorOk);
    status.fresh = data.simulatedSensorFrameFresh;
    status.calibrated = data.smokeSensorCalibrated && data.weatherSensorCalibrated;
    status.fault = data.simulatedSensorFault || data.driverBridgeFaultDetected;
    std::ostringstream detail;
    detail << "smoke/fire " << ((data.smokeDetected || data.fireDetected) ? "detected" : "not detected")
        << ", temp " << data.temperatureC << " C, humidity " << data.humidityPercent
        << "%, wind " << data.windKph << " kph";
    status.detail = detail.str();
    return status;
}

std::string SmokeWeatherDriverInterface::fakeReading(const SensorData& data) const {
    std::ostringstream out;
    out << "Fake smoke/weather driver reading: smoke " << (data.smokeDetected ? "detected" : "not detected")
        << ", fire " << (data.fireDetected ? "detected" : "not detected")
        << ", temperature " << data.temperatureC << " C"
        << ", humidity " << data.humidityPercent << "%"
        << ", wind " << data.windKph << " kph"
        << ", rapid shift " << (data.rapidWeatherShift ? "yes" : "no") << ".";
    return out.str();
}

std::string SmokeWeatherDriverInterface::realDriverNotes() const {
    return "SmokeWeatherDriverInterface real notes: report smoke/fire sensor health, temperature, humidity, wind, pressure if available, trend, timestamp freshness, and sensor fault state; fire/smoke cues must trigger retreat guidance and private alerts.";
}

HardwareDriverStatus GeofenceDriverInterface::fakeStatus(const SensorData& data) const {
    HardwareDriverStatus status;
    status.driverName = "GeofenceDriverInterface";
    status.mode = data.simulatedHardwareMode ? "fake geofence driver" : "real geofence driver placeholder";
    status.installed = data.hardwareDriversInstalled;
    status.online = data.sensorDriverBridgeOnline && data.gpsOk && data.geofenceConfigured;
    status.fresh = data.simulatedSensorFrameFresh;
    status.calibrated = data.gpsCalibrated;
    status.fault = data.driverBridgeFaultDetected || !data.geofenceConfigured;
    status.detail = "safe zones " + std::to_string(data.safeZoneNames.size())
        + ", no-go zones " + std::to_string(data.noGoZoneNames.size());
    return status;
}

std::string GeofenceDriverInterface::fakeReading(const SensorData& data) const {
    std::ostringstream out;
    out << "Fake geofence driver reading: configured " << (data.geofenceConfigured ? "yes" : "no")
        << ", safe zones " << listItemsOrNone(data.safeZoneNames)
        << ", no-go zones " << listItemsOrNone(data.noGoZoneNames)
        << ". Missing geofence keeps movement disabled.";
    return out.str();
}

std::string GeofenceDriverInterface::realDriverNotes() const {
    return "GeofenceDriverInterface real notes: compare fresh location to private safe zones, no-go zones, habitat buffers, roads, cliffs, water edges, and property lines; uncertain position must stop or retreat to known safe memory.";
}

HardwareDriverStatus PayloadDriverInterface::fakeStatus(const SensorData& data) const {
    HardwareDriverStatus status;
    status.driverName = "PayloadDriverInterface";
    status.mode = data.simulatedHardwareMode ? "fake payload/load driver" : "real payload/load driver placeholder";
    status.installed = data.hardwareDriversInstalled;
    status.online = data.sensorDriverBridgeOnline;
    status.fresh = data.simulatedSensorFrameFresh;
    status.calibrated = true;
    status.fault = data.simulatedSensorFault || data.payloadKg > 20.0 || data.driverBridgeFaultDetected;
    std::ostringstream detail;
    detail << "payload " << data.payloadKg << " kg";
    status.detail = detail.str();
    return status;
}

std::string PayloadDriverInterface::fakeReading(const SensorData& data) const {
    std::ostringstream out;
    out << "Fake payload/load driver reading: payload " << data.payloadKg
        << " kg; unsafe load flags must refuse carrying and protect stability.";
    return out.str();
}

std::string PayloadDriverInterface::realDriverNotes() const {
    return "PayloadDriverInterface real notes: report payload estimate, center-of-mass concern, overload, shifting load, and freshness; overload must prevent movement or carrying.";
}

HardwareDriverStatus MedicalRequestDriverInterface::fakeStatus(const SensorData& data) const {
    HardwareDriverStatus status;
    status.driverName = "MedicalRequestDriverInterface";
    status.mode = data.simulatedHardwareMode ? "fake medical request/vitals prompt driver" : "real non-invasive medical input placeholder";
    status.installed = data.hardwareDriversInstalled;
    status.online = data.sensorDriverBridgeOnline || data.voiceInterfaceConfigured || data.phoneAlertConfigured;
    status.fresh = data.simulatedSensorFrameFresh;
    status.calibrated = true;
    status.fault = data.driverBridgeFaultDetected;
    status.detail = data.medicalRequest ? "medical request active" : "no medical request";
    return status;
}

std::string MedicalRequestDriverInterface::fakeReading(const SensorData& data) const {
    std::ostringstream out;
    out << "Fake medical request driver reading: request " << (data.medicalRequest ? "active" : "not active")
        << ", injury severity " << toString(data.injurySeverity)
        << ", privacy consent " << (data.medicalPrivacyConsent ? "yes" : "no")
        << ". Guidance remains non-invasive and educational.";
    return out.str();
}

std::string MedicalRequestDriverInterface::realDriverNotes() const {
    return "MedicalRequestDriverInterface real notes: accept owner/family help requests, button/voice prompts, optional non-invasive vitals devices, privacy consent, and freshness; it must not diagnose beyond field guidance.";
}

HardwareDriverStatus SolarChargeDriverInterface::fakeStatus(const SensorData& data) const {
    HardwareDriverStatus status;
    status.driverName = "SolarChargeDriverInterface";
    status.mode = data.simulatedHardwareMode ? "fake solar charge driver" : "real solar charge controller placeholder";
    status.installed = data.hardwareDriversInstalled;
    status.online = data.sensorDriverBridgeOnline && data.solarPanelConnected && data.solarChargeControllerOk;
    status.fresh = data.simulatedSensorFrameFresh;
    status.calibrated = data.solarChargeControllerOk;
    const bool overVoltage = data.batteryMaxChargeVoltage > 0.0 && data.batteryVoltage >= data.batteryMaxChargeVoltage;
    const bool overCurrent = data.solarControllerMaxCurrentAmps > 0.0
        && data.solarChargeCurrentAmps > data.solarControllerMaxCurrentAmps;
    status.fault = data.solarChargingFaultDetected
        || data.solarOverchargeRiskDetected
        || data.solarOvercurrentDetected
        || data.solarControllerDisconnectActive
        || overVoltage
        || overCurrent
        || data.batteryTemperatureHigh
        || data.driverBridgeFaultDetected;
    std::ostringstream detail;
    detail << data.solarPanelWatts << " W panel, " << data.sunHours
        << " sun hours, charging " << (data.solarChargingActive ? "active" : "not active")
        << ", battery " << data.batteryPercent << "%/" << data.batteryVoltage << " V"
        << ", current " << data.solarChargeCurrentAmps << " A";
    status.detail = detail.str();
    return status;
}

std::string SolarChargeDriverInterface::fakeReading(const SensorData& data) const {
    std::ostringstream out;
    out << "Fake solar charge driver reading: panel connected " << (data.solarPanelConnected ? "yes" : "no")
        << ", deployed " << (data.solarPanelDeployed ? "yes" : "no")
        << ", controller " << (data.solarChargeControllerOk ? "OK" : "not verified")
        << ", charging " << (data.solarChargingActive ? "active" : "not active")
        << ", battery " << data.batteryPercent << "% at " << data.batteryVoltage << " V"
        << ", max charge " << data.batteryMaxChargeVoltage << " V"
        << ", charge current " << data.solarChargeCurrentAmps << " A / max " << data.solarControllerMaxCurrentAmps << " A"
        << ", overcharge risk " << (data.solarOverchargeRiskDetected ? "detected" : "not reported")
        << ", overcurrent " << (data.solarOvercurrentDetected ? "detected" : "not reported")
        << ", controller disconnect " << (data.solarControllerDisconnectActive ? "active" : "not active")
        << ", battery temperature " << (data.batteryTemperatureHigh ? "high" : "normal/not reported")
        << ".";
    return out.str();
}

std::string SolarChargeDriverInterface::realDriverNotes() const {
    return "SolarChargeDriverInterface real notes: report panel voltage/current, charge current, controller state, battery chemistry profile, battery voltage, full-charge limit, temperature, fault codes, overcharge/overcurrent protection, reverse-current protection, and load disconnect; unsafe charging must disconnect safely.";
}

HardwareDriverStatus WaterFilterStorageDriverInterface::fakeStatus(const SensorData& data) const {
    HardwareDriverStatus status;
    status.driverName = "WaterFilterStorageDriverInterface";
    status.mode = data.simulatedHardwareMode ? "fake water filter/storage driver" : "real water filter/storage placeholder";
    status.installed = data.hardwareDriversInstalled;
    status.online = data.waterFilterAvailable || data.cleanWaterContainersAvailable;
    status.fresh = data.simulatedSensorFrameFresh;
    status.calibrated = data.cleanWaterContainersAvailable;
    status.fault = data.driverBridgeFaultDetected;
    status.detail = std::string("filter ") + (data.waterFilterAvailable ? "available" : "not confirmed")
        + ", clean containers " + (data.cleanWaterContainersAvailable ? "available" : "not confirmed");
    return status;
}

std::string WaterFilterStorageDriverInterface::fakeReading(const SensorData& data) const {
    return std::string("Fake water filter/storage driver reading: filter ")
        + (data.waterFilterAvailable ? "available" : "not confirmed")
        + ", clean containers " + (data.cleanWaterContainersAvailable ? "available" : "not confirmed")
        + ". It tracks readiness only; it cannot certify water safe without treatment evidence.";
}

std::string WaterFilterStorageDriverInterface::realDriverNotes() const {
    return "WaterFilterStorageDriverInterface real notes: report filter presence, cartridge life if available, clean/dirty container separation, storage date labels, and contamination flags; it must never mark water potable from weak evidence.";
}

HardwareDriverStatus FoodStorageDriverInterface::fakeStatus(const SensorData& data) const {
    HardwareDriverStatus status;
    status.driverName = "FoodStorageDriverInterface";
    status.mode = data.simulatedHardwareMode ? "fake food drying/storage driver" : "real food storage placeholder";
    status.installed = data.hardwareDriversInstalled;
    status.online = data.foodDryingAvailable || data.dryFoodStorageAvailable;
    status.fresh = data.simulatedSensorFrameFresh;
    status.calibrated = data.dryFoodStorageAvailable;
    status.fault = data.foodSpoilageRisk || data.driverBridgeFaultDetected;
    status.detail = std::string("drying ") + (data.foodDryingAvailable ? "available" : "not confirmed")
        + ", dry storage " + (data.dryFoodStorageAvailable ? "available" : "not confirmed");
    return status;
}

std::string FoodStorageDriverInterface::fakeReading(const SensorData& data) const {
    return std::string("Fake food storage driver reading: drying setup ")
        + (data.foodDryingAvailable ? "available" : "not confirmed")
        + ", dry storage " + (data.dryFoodStorageAvailable ? "available" : "not confirmed")
        + ", spoilage risk " + (data.foodSpoilageRisk ? "elevated" : "not reported")
        + ". It supports pantry logging, not unsafe food certification.";
}

std::string FoodStorageDriverInterface::realDriverNotes() const {
    return "FoodStorageDriverInterface real notes: report storage temperature/humidity if available, container status, label dates, spoilage flags, and pest/moisture concerns; uncertain food remains unsafe to eat.";
}

HardwareDriverStatus CommunicationsDriverInterface::fakeStatus(const SensorData& data) const {
    HardwareDriverStatus status;
    status.driverName = "CommunicationsDriverInterface";
    status.mode = data.simulatedHardwareMode ? "fake communication/phone driver" : "real communication/phone driver placeholder";
    status.installed = data.hardwareDriversInstalled;
    status.online = data.communicationLinkOk || data.phoneAlertConfigured;
    status.fresh = !data.simulatedCommandTimeout;
    status.calibrated = data.phoneAlertConfigured || data.offlineVoiceCommandsCached;
    status.fault = data.driverBridgeFaultDetected || data.simulatedCommandTimeout;
    status.detail = std::string("communication link ") + (data.communicationLinkOk ? "OK" : "not verified")
        + ", phone alerts " + (data.phoneAlertConfigured ? "configured" : "not configured")
        + ", offline voice " + (data.offlineVoiceCommandsCached ? "cached" : "not cached");
    return status;
}

std::string CommunicationsDriverInterface::fakeReading(const SensorData& data) const {
    return std::string("Fake communication driver reading: link ")
        + (data.communicationLinkOk ? "OK" : "not verified")
        + ", phone alerts " + (data.phoneAlertConfigured ? "configured" : "not configured")
        + ", emergency services availability " + (data.emergencyServicesAvailable ? "possible" : "not available")
        + ". Private details still require owner/family authorization.";
}

std::string CommunicationsDriverInterface::realDriverNotes() const {
    return "CommunicationsDriverInterface real notes: report link quality, paired owner device, offline fallback, emergency message delivery status, timestamps, and privacy lock state; it must not share private reports with outsiders.";
}

HardwareDriverStatus OwnerAlertDriverInterface::fakeStatus(const SensorData& data) const {
    HardwareDriverStatus status;
    status.driverName = "OwnerAlertDriverInterface";
    status.mode = data.simulatedHardwareMode ? "fake owner alert driver" : "real owner alert driver placeholder";
    status.installed = data.hardwareDriversInstalled;
    status.online = data.actuatorDriverBridgeOnline && data.ownerAlertLinkOk;
    status.fresh = !data.simulatedCommandTimeout;
    status.calibrated = data.ownerAlertTestPassed;
    status.fault = data.simulatedActuatorFault || data.driverBridgeFaultDetected;
    status.detail = "silent owner/family alerts only";
    return status;
}

std::string OwnerAlertDriverInterface::fakeOutputPreview(const SensorData& data) const {
    if (data.simulatedActuatorFault || data.driverBridgeFaultDetected) {
        return "Fake owner alert output: log alert and avoid nonessential outputs because actuator/driver fault is active.";
    }
    return "Fake owner alert output: send private silent owner/family alert only, with shortest useful safety message.";
}

std::string OwnerAlertDriverInterface::realDriverNotes() const {
    return "OwnerAlertDriverInterface real notes: support paired owner/family alerts, delivery status, haptic/silent mode, privacy lock, and emergency escalation only when authorized or life safety requires minimum sharing.";
}

HardwareDriverStatus MotorDriverInterface::fakeStatus(const SensorData& data) const {
    HardwareDriverStatus status;
    status.driverName = "MotorDriverInterface";
    status.mode = data.simulatedHardwareMode ? "fake motor driver" : "real motor driver placeholder";
    status.installed = data.hardwareDriversInstalled;
    status.online = data.actuatorDriverBridgeOnline && data.motorControllerOk && data.driveBaseOk;
    status.fresh = !data.simulatedCommandTimeout;
    status.calibrated = data.motorStopTestPassed;
    status.fault = data.simulatedActuatorFault || data.driverBridgeFaultDetected || !data.safeStopOnFaultOk;
    status.detail = data.motorOutputArmed ? "motor output armed flag set" : "motor output disarmed";
    return status;
}

std::string MotorDriverInterface::fakeOutputPreview(const SensorData& data) const {
    if (data.simulatedActuatorFault || data.driverBridgeFaultDetected || !data.safeStopOnFaultOk) {
        return "Fake motor driver output: STOP_MOTION because actuator fault, driver fault, or safe-stop failure is active.";
    }
    if (!data.motorOutputArmed || data.simulatedHardwareMode) {
        return "Fake motor driver output: STOP_MOTION because motor output is disarmed or simulation mode is active.";
    }
    return "Fake motor driver output: would accept only bounded low-speed movement after geofence, obstacle, emergency stop, and owner authentication checks.";
}

std::string MotorDriverInterface::realDriverNotes() const {
    return "MotorDriverInterface real notes: accept only speed-limited commands with timeout, current/temperature monitoring, stop-on-fault, neutral default, and no support for forceful or harmful behavior.";
}

HardwareDriverStatus SteeringDriverInterface::fakeStatus(const SensorData& data) const {
    HardwareDriverStatus status;
    status.driverName = "SteeringDriverInterface";
    status.mode = data.simulatedHardwareMode ? "fake steering driver" : "real steering driver placeholder";
    status.installed = data.hardwareDriversInstalled;
    status.online = data.actuatorDriverBridgeOnline && data.steeringOk;
    status.fresh = !data.simulatedCommandTimeout;
    status.calibrated = data.motorStopTestPassed;
    status.fault = data.simulatedActuatorFault || data.driverBridgeFaultDetected || !data.safeStopOnFaultOk;
    status.detail = "bounded steering only; neutral default";
    return status;
}

std::string SteeringDriverInterface::fakeOutputPreview(const SensorData& data) const {
    if (data.simulatedActuatorFault || data.driverBridgeFaultDetected || !data.safeStopOnFaultOk) {
        return "Fake steering output: NEUTRAL/STOP because actuator fault, driver fault, or safe-stop failure is active.";
    }
    if (!data.motorOutputArmed || data.simulatedHardwareMode) {
        return "Fake steering output: NEUTRAL because motor/steering output is disarmed or simulation mode is active.";
    }
    return "Fake steering output: would accept only bounded low-rate steering after obstacle, geofence, and owner-following checks.";
}

std::string SteeringDriverInterface::realDriverNotes() const {
    return "SteeringDriverInterface real notes: accept bounded steering angles or rates only, with neutral default, timeout, limit checks, and safe stop on any fault.";
}

HardwareDriverStatus LightSpeakerDriverInterface::fakeStatus(const SensorData& data) const {
    HardwareDriverStatus status;
    status.driverName = "LightSpeakerDriverInterface";
    status.mode = data.simulatedHardwareMode ? "fake light/speaker driver" : "real light/speaker driver placeholder";
    status.installed = data.hardwareDriversInstalled;
    status.online = data.actuatorDriverBridgeOnline && data.speakerLightOk && data.ownerAlertLinkOk;
    status.fresh = !data.simulatedCommandTimeout;
    status.calibrated = data.ownerAlertTestPassed;
    status.fault = data.simulatedActuatorFault || data.driverBridgeFaultDetected;
    status.detail = "private alerts and gentle signaling only";
    return status;
}

std::string LightSpeakerDriverInterface::fakeOutputPreview(const SensorData& data) const {
    if (data.simulatedActuatorFault || data.driverBridgeFaultDetected) {
        return "Fake light/speaker output: disabled except critical owner alert logging because actuator/driver fault is active.";
    }
    return "Fake light/speaker output: private owner/family alert, low-intensity light, and calm sound only; no intimidation or harassment.";
}

std::string LightSpeakerDriverInterface::realDriverNotes() const {
    return "LightSpeakerDriverInterface real notes: support private alerts, low-intensity signaling, and emergency visibility; wildlife deterrence must stay non-harmful and avoid sensitive habitats.";
}

std::string HardwareDriverInterfaceSuiteModule::fakeDriverStatusReport(const SensorData& data) const {
    GpsDriverInterface gps;
    BatteryDriverInterface battery;
    ObstacleDriverInterface obstacle;
    EmergencyStopDriverInterface emergencyStop;
    InfraredThermalDriverInterface infraredThermal;
    ImuCompassDriverInterface imuCompass;
    CameraDriverInterface camera;
    SmokeWeatherDriverInterface smokeWeather;
    GeofenceDriverInterface geofence;
    PayloadDriverInterface payload;
    MedicalRequestDriverInterface medicalRequest;
    SolarChargeDriverInterface solarCharge;
    WaterFilterStorageDriverInterface waterFilterStorage;
    FoodStorageDriverInterface foodStorage;
    CommunicationsDriverInterface communications;
    OwnerAlertDriverInterface ownerAlert;
    MotorDriverInterface motor;
    SteeringDriverInterface steering;
    LightSpeakerDriverInterface lightSpeaker;
    return joinLines({
        "Hardware driver interface status",
        driverStatusLine(gps.fakeStatus(data)),
        driverStatusLine(battery.fakeStatus(data)),
        driverStatusLine(obstacle.fakeStatus(data)),
        driverStatusLine(emergencyStop.fakeStatus(data)),
        driverStatusLine(infraredThermal.fakeStatus(data)),
        driverStatusLine(imuCompass.fakeStatus(data)),
        driverStatusLine(camera.fakeStatus(data)),
        driverStatusLine(smokeWeather.fakeStatus(data)),
        driverStatusLine(geofence.fakeStatus(data)),
        driverStatusLine(payload.fakeStatus(data)),
        driverStatusLine(medicalRequest.fakeStatus(data)),
        driverStatusLine(solarCharge.fakeStatus(data)),
        driverStatusLine(waterFilterStorage.fakeStatus(data)),
        driverStatusLine(foodStorage.fakeStatus(data)),
        driverStatusLine(communications.fakeStatus(data)),
        driverStatusLine(ownerAlert.fakeStatus(data)),
        driverStatusLine(motor.fakeStatus(data)),
        driverStatusLine(steering.fakeStatus(data)),
        driverStatusLine(lightSpeaker.fakeStatus(data))
    });
}

std::string HardwareDriverInterfaceSuiteModule::fakeSensorReadings(const SensorData& data) const {
    GpsDriverInterface gps;
    BatteryDriverInterface battery;
    ObstacleDriverInterface obstacle;
    EmergencyStopDriverInterface emergencyStop;
    InfraredThermalDriverInterface infraredThermal;
    ImuCompassDriverInterface imuCompass;
    CameraDriverInterface camera;
    SmokeWeatherDriverInterface smokeWeather;
    GeofenceDriverInterface geofence;
    PayloadDriverInterface payload;
    MedicalRequestDriverInterface medicalRequest;
    SolarChargeDriverInterface solarCharge;
    WaterFilterStorageDriverInterface waterFilterStorage;
    FoodStorageDriverInterface foodStorage;
    CommunicationsDriverInterface communications;
    return joinLines({
        "Fake sensor driver readings",
        gps.fakeReading(data),
        battery.fakeReading(data),
        obstacle.fakeReading(data),
        emergencyStop.fakeReading(data),
        infraredThermal.fakeReading(data),
        imuCompass.fakeReading(data),
        camera.fakeReading(data),
        smokeWeather.fakeReading(data),
        geofence.fakeReading(data),
        payload.fakeReading(data),
        medicalRequest.fakeReading(data),
        solarCharge.fakeReading(data),
        waterFilterStorage.fakeReading(data),
        foodStorage.fakeReading(data),
        communications.fakeReading(data)
    });
}

std::string HardwareDriverInterfaceSuiteModule::fakeActuatorOutputs(const SensorData& data) const {
    OwnerAlertDriverInterface ownerAlert;
    MotorDriverInterface motor;
    SteeringDriverInterface steering;
    LightSpeakerDriverInterface lightSpeaker;
    return joinLines({
        "Fake actuator driver outputs",
        ownerAlert.fakeOutputPreview(data),
        motor.fakeOutputPreview(data),
        steering.fakeOutputPreview(data),
        lightSpeaker.fakeOutputPreview(data)
    });
}

std::string HardwareDriverInterfaceSuiteModule::fakeControllerStatusReport(const SensorData& data) const {
    return joinLines({
        "Fake controller interface status",
        std::string("- FakeOwnerAuthController: ") + ((data.realOwnerAuthenticationConfigured || data.ownerAuthenticated) ? "ready for owner-gated commands." : "locked until owner authentication hardware is configured."),
        std::string("- FakeEmergencyStopController: ") + (data.emergencyStopCircuitOk ? "stop circuit available." : "missing; motion must stay disabled."),
        std::string("- FakeMotionSafetyController: ") + ((data.motorControllerOk && data.driveBaseOk && data.safeStopOnFaultOk) ? "bounded motion path available." : "motion locked to STOP_MOTION."),
        std::string("- FakeSteeringSafetyController: ") + ((data.steeringOk && data.safeStopOnFaultOk) ? "bounded steering path available." : "steering neutral/locked."),
        std::string("- FakeNavigationController: ") + ((data.gpsOk && data.imuOk && data.obstacleSensorOk && data.geofenceConfigured) ? "route advisory available." : "route advisory limited; stop or ask owner."),
        std::string("- FakeSensorFusionAwarenessController: ") + ((data.sensorDriverBridgeOnline && data.simulatedSensorFrameFresh) ? "fresh awareness frame available." : "awareness limited; treat as uncertain."),
        std::string("- FakePowerBmsController: ") + ((data.batteryMonitorOk && !data.batteryTemperatureHigh) ? "battery telemetry acceptable." : "battery protection required."),
        std::string("- FakeSolarChargeController: ") + ((data.solarChargeControllerOk && !data.solarOverchargeRiskDetected && !data.solarOvercurrentDetected) ? "controller-managed charging allowed." : "charging held or locked out."),
        std::string("- FakeOwnerAlertController: ") + (data.ownerAlertLinkOk ? "private owner/family alert path available." : "alert path missing; keep reports local and visible to owner only."),
        std::string("- FakeCommunicationController: ") + (data.communicationLinkOk ? "communication link available." : "offline/local guidance only."),
        std::string("- FakeMedicalAssistController: ") + (data.medicalRequest ? "medical support active." : "standby for non-invasive first-aid prompts."),
        std::string("- FakeWaterFoodController: ") + ((data.waterFilterAvailable || data.cleanWaterContainersAvailable || data.foodDryingAvailable || data.dryFoodStorageAvailable) ? "resource support available." : "resource support not confirmed."),
        std::string("- FakePayloadStabilityController: ") + ((data.payloadKg <= 10.0 && !data.steepOrSlipperyTerrain) ? "payload/stability acceptable." : "reduce load or stop movement."),
        std::string("- FakePrivacyStorageController: ") + ((data.privateStorageConfigured && data.privateStorageEncryptionActive) ? "encrypted private storage ready." : "demo/private labels only; real deployment blocked.")
    });
}

std::string HardwareDriverInterfaceSuiteModule::fakeControllerOutputs(const SensorData& data) const {
    const bool motionAllowed = data.realHardwareMode
        && data.motorOutputArmed
        && data.ownerAuthenticated
        && data.emergencyStopCircuitOk
        && data.safeStopOnFaultOk
        && data.motorControllerOk
        && data.driveBaseOk
        && data.steeringOk
        && data.obstacleSensorOk
        && data.geofenceConfigured
        && !data.simulatedObstacleAhead
        && !data.simulatedEmergencyStopPressed
        && !data.simulatedCommandTimeout
        && !data.simulatedActuatorFault
        && !data.driverBridgeFaultDetected
        && !data.solarOverchargeRiskDetected
        && !data.batteryTemperatureHigh;
    const bool chargeAllowed = data.solarPanelConnected
        && data.solarChargeControllerOk
        && !data.solarOverchargeRiskDetected
        && !data.solarOvercurrentDetected
        && !data.solarControllerDisconnectActive
        && !data.batteryTemperatureHigh;

    return joinLines({
        "Fake controller safe outputs",
        std::string("- Motion command: ") + (motionAllowed ? "LOW_SPEED_ALLOWED with owner-supervised limits." : "STOP_MOTION."),
        std::string("- Steering command: ") + (motionAllowed ? "BOUNDED_STEERING_ALLOWED." : "NEUTRAL."),
        std::string("- Solar charging command: ") + (chargeAllowed ? "ALLOW_CONTROLLER_MANAGED_CHARGE." : "HOLD_OR_DISCONNECT_CHARGE."),
        std::string("- Owner alert command: ") + ((data.ownerAlertLinkOk && (data.ownerPresent || data.familyPresent)) ? "PRIVATE_SILENT_ALERT_READY." : "LOCAL_LOG_ONLY."),
        std::string("- Communications command: ") + (data.communicationLinkOk ? "OWNER/EMERGENCY_MINIMUM_NEEDED_ONLY." : "OFFLINE_MODE."),
        std::string("- Medical assist command: ") + (data.medicalRequest ? "CALM_NON_INVASIVE_FIRST_AID_PROMPTS." : "MONITOR_ONLY."),
        std::string("- Privacy storage command: ") + (data.privateStorageEncryptionActive ? "ENCRYPTED_PRIVATE_WRITE_ALLOWED_AFTER_AUTH." : "DEMO_TEXT_ONLY_OR_LOCKED."),
        "- Controller rule: every output remains advisory, bounded, authenticated where needed, and non-harmful; any uncertainty fails closed."
    });
}

std::string HardwareDriverInterfaceSuiteModule::realDriverClassPlan() const {
    return joinLines({
        "Real/fake driver class plan",
        "- GpsDriverInterface: fake position now; later replace with real GPS/localization driver.",
        "- BatteryDriverInterface: fake battery percent now; later replace with voltage/current/temperature monitor.",
        "- ObstacleDriverInterface: fake obstacle flags now; later replace with ultrasonic/lidar/depth/bumper/cliff sensors.",
        "- EmergencyStopDriverInterface: fake stop flag now; later replace with physical hard-stop circuit status.",
        "- InfraredThermalDriverInterface: fake IR/thermal cues now; later replace with privacy-aware thermal camera and infrared motion/heat-signature drivers.",
        "- ImuCompassDriverInterface: fake orientation/stability now; later replace with IMU, compass, tilt, and stuck/fall sensing.",
        "- CameraDriverInterface: fake visual health/framing now; later replace with privacy-aware camera/terrain/obstacle cue driver.",
        "- SmokeWeatherDriverInterface: fake smoke, fire, temperature, humidity, wind, and trend now; later replace with smoke/fire/weather station drivers.",
        "- GeofenceDriverInterface: fake safe/no-go boundary checks now; later replace with private geofence and map-boundary driver.",
        "- PayloadDriverInterface: fake payload/load reading now; later replace with load-cell or carrying-capacity sensor.",
        "- MedicalRequestDriverInterface: fake medical request/vitals prompt now; later replace with non-invasive request button, voice, or approved vitals input.",
        "- SolarChargeDriverInterface: fake solar charging status now; later replace with charge controller and battery charging telemetry.",
        "- WaterFilterStorageDriverInterface: fake water-filter/container readiness now; later replace with filter-life, clean-container, and storage sensors.",
        "- FoodStorageDriverInterface: fake pantry/drying readiness now; later replace with humidity/temperature/container/spoilage flag sensors.",
        "- CommunicationsDriverInterface: fake phone/radio/private link now; later replace with paired owner device, radio, phone, or local network driver.",
        "- OwnerAlertDriverInterface: fake private alert output now; later replace with paired haptic/phone/light alert hardware.",
        "- MotorDriverInterface: fake STOP_MOTION output now; later replace with bounded motor controller commands.",
        "- SteeringDriverInterface: fake neutral steering output now; later replace with bounded steering controller commands.",
        "- LightSpeakerDriverInterface: fake alert output now; later replace with private alert light/speaker hardware.",
        "All real drivers must preserve the same safety contract: report freshness and faults, never bypass ethics, and fail closed to STOP_MOTION."
    });
}

std::string HardwareDriverInterfaceSuiteModule::driverSwapChecklist() const {
    return joinLines({
        "Driver swap checklist",
        "1. Keep fake drivers as the bench-test default.",
        "2. Add one real driver at a time behind the same interface shape.",
        "3. Verify timestamps, calibration, fault flags, and unplugged/disconnected behavior.",
        "4. Confirm real motor output remains disabled until emergency stop, safe stop, geofence, obstacle, battery, owner alert, and authentication pass.",
        "5. Use the complete fake roster as the checklist before field use: location, orientation, vision, IR/thermal, weather/smoke, geofence, payload, medical request, battery/solar, water/food readiness, communications, owner alert, motor, steering, and light/speaker.",
        "6. If a real driver disagrees with another sensor or goes stale, stop motion and alert owner/family privately."
    });
}

std::string HardwareDriverInterfaceSuiteModule::realControllerClassPlan() const {
    return joinLines({
        "Real/fake controller class plan",
        "- FakeOwnerAuthController: owner-only shutdown/override/report controls now; later replace with paired key, secure token, PIN, or trusted hardware controller.",
        "- FakeEmergencyStopController: stop/lockout decision now; later replace with hard-wired stop and verified stop-state monitor.",
        "- FakeMotionSafetyController: STOP_MOTION default now; later replace with bounded speed, current, temperature, timeout, and safe braking controller.",
        "- FakeSteeringSafetyController: neutral default now; later replace with bounded steering angle/rate controller and limit feedback.",
        "- FakeNavigationController: route advisory now; later connect GPS/IMU/geofence/obstacle fusion to low-speed waypoints.",
        "- FakeSensorFusionAwarenessController: simulated awareness now; later combine thermal, IR, camera, smoke/weather, obstacle, GPS, IMU, and wildlife cues with confidence scores.",
        "- FakePowerBmsController: battery protection logic now; later connect real BMS, voltage/current/temperature, low-voltage disconnect, and fault codes.",
        "- FakeSolarChargeController: charge/hold/disconnect logic now; later connect real charge controller telemetry and overcharge/overcurrent protection.",
        "- FakeOwnerAlertController: private alert decision now; later connect haptic, phone, local radio, light, or dashboard alert hardware.",
        "- FakeCommunicationController: message routing now; later connect paired phone/radio/offline emergency channel with privacy lock.",
        "- FakeMedicalAssistController: non-invasive prompt control now; later connect owner request button, approved vitals input, and emergency report helper.",
        "- FakeWaterFoodController: resource readiness logic now; later connect filter-life, clean-container, storage humidity/temperature, and spoilage sensors.",
        "- FakePayloadStabilityController: load/stability gate now; later connect load cells, tilt, center-of-mass estimate, and terrain stability checks.",
        "- FakePrivacyStorageController: demo privacy locks now; later connect encrypted storage, owner-held keys, integrity checks, and redaction."
    });
}

std::string HardwareDriverInterfaceSuiteModule::controllerSwapChecklist() const {
    return joinLines({
        "Controller swap checklist",
        "1. Keep fake controllers as the bench-test default until every real controller proves fail-closed behavior.",
        "2. Swap one controller at a time: authentication, emergency stop, power/BMS, solar charging, motion, steering, alerts, communication, then higher-level navigation.",
        "3. Before enabling movement, prove emergency stop, safe-stop-on-fault, obstacle/geofence lockout, owner authentication, low-speed limits, and timeout behavior.",
        "4. Before enabling charging, prove controller/BMS telemetry, overcharge/overcurrent protection, battery temperature fault response, fuses, polarity, and disconnect behavior.",
        "5. Before enabling private storage, prove encryption is active, keys are not in source code, integrity checks work, and unauthenticated reads/writes fail.",
        "6. If any controller is stale, missing, conflicted, or uncertain, hold output, stop motion, alert owner/family privately, and remain in demo/advisory mode."
    });
}

std::string OwnerDashboardModule::buildDashboardSnapshot(
    BotState state,
    const SensorData& data,
    std::size_t reportCount,
    std::size_t actionCount,
    std::size_t auditCount) const {
    std::ostringstream out;
    out << "CONSERVATION GUARDIAN OWNER DASHBOARD SNAPSHOT\n";
    out << "Keep private: may include location, reports, routes, medical/security status, and resources.\n\n";
    out << "OVERVIEW\n";
    out << "State: " << toString(state) << "\n";
    out << "Location: " << (data.locationKnown ? data.locationDescription : "unknown") << "\n";
    out << "Owner authenticated: " << (data.ownerAuthenticated ? "yes" : "no") << "\n";
    out << "Dashboard configured: " << (data.ownerDashboardConfigured ? "yes" : "no") << "\n";
    out << "Private dashboard access: " << (data.ownerDashboardPrivateAccessOk ? "ok" : "not verified") << "\n";
    out << "Emergency controls visible: " << (data.dashboardEmergencyControlsVisible ? "yes" : "no") << "\n\n";

    out << "CURRENT SAFETY\n";
    out << "Threat level: " << data.threatLevel << "/10\n";
    out << "Weather: " << data.temperatureC << " C, wind " << data.windKph << " kph, humidity " << data.humidityPercent << "%\n";
    out << "Fire/smoke: " << ((data.fireDetected || data.smokeDetected) ? "detected" : "not detected") << "\n";
    out << "Medical request: " << (data.medicalRequest ? "yes" : "no") << ", injury severity " << toString(data.injurySeverity) << "\n";
    out << "Resources: battery " << data.batteryPercent << "%, water " << data.waterLiters << " L, food hours " << data.foodHours << "\n\n";

    out << "MAP AND HARDWARE\n";
    out << "Safe zones: " << listItemsOrNone(data.safeZoneNames) << "\n";
    out << "No-go zones: " << listItemsOrNone(data.noGoZoneNames) << "\n";
    out << "Hardware interface: " << (data.hardwareInterfaceConnected ? "connected" : "not connected") << "\n";
    out << "Driver bridge: " << (data.hardwareDriversInstalled ? "installed" : "not installed") << ", motor output "
        << (data.motorOutputArmed ? "armed" : "disarmed") << "\n\n";

    out << "LOG COUNTS\n";
    out << "Situation reports: " << reportCount << "\n";
    out << "Action log entries: " << actionCount << "\n";
    out << "Audit log entries: " << auditCount << "\n";
    out << "Dashboard notes: " << listItemsOrNone(data.dashboardNotes) << "\n\n";
    out << dashboardPanelPlan() << "\n";
    out << ownerActionPlan() << "\n";
    out << privacyPlan() << "\n";
    return out.str();
}

bool OwnerDashboardModule::saveDashboardSnapshot(
    const std::string& filePath,
    BotState state,
    const SensorData& data,
    std::size_t reportCount,
    std::size_t actionCount,
    std::size_t auditCount,
    std::string& status) const {
    return writeTextFile(
        filePath,
        buildDashboardSnapshot(state, data, reportCount, actionCount, auditCount),
        status,
        "Owner dashboard snapshot");
}

bool OwnerDashboardModule::loadDashboardSnapshotText(const std::string& filePath, std::string& contents, std::string& status) const {
    return readTextFile(filePath, contents, status, "Owner dashboard snapshot");
}

std::string OwnerDashboardModule::dashboardPanelPlan() const {
    return joinLines({
        "Dashboard panel plan",
        "- Current state, best judgment, and highest-priority alert.",
        "- Private reports, numbered log export, and audit summary.",
        "- Weather/fire/smoke, route/map/geofence, resources, and medical prompt status.",
        "- Hardware, calibration, driver bridge, emergency stop, and field-test readiness.",
        "- Local knowledge, offline library, owner profile, and emergency contacts."
    });
}

std::string OwnerDashboardModule::ownerActionPlan() const {
    return joinLines({
        "Owner action plan",
        "- Buttons should be simple: acknowledge alert, show reports, export log, call for help, navigate to safe zone, request medical guidance, stop motion.",
        "- Emergency shutdown and owner override must require verified owner authentication.",
        "- Any real movement command must show why it is allowed and what will stop it.",
        "- The dashboard should prefer calm recommendations over noisy alarms unless immediate life safety is at stake."
    });
}

std::string OwnerDashboardModule::privacyPlan() const {
    return "Dashboard privacy plan: display private location, medical, security, resource, and route details only to authenticated owner/family devices; outsiders get no internal assessment.";
}

std::string SecurityAccessModule::accessStatus(const SensorData& data) const {
    std::ostringstream out;
    out << "Security access status\n";
    out << "Owner authenticated: " << (data.ownerAuthenticated ? "yes" : "no") << ". ";
    out << "Security keys configured: " << (data.securityKeysConfigured ? "yes" : "no") << ". ";
    out << "Trusted controller present: " << (data.trustedControllerPresent ? "yes" : "no") << ".\n";
    out << "Outsider command blocked: " << (data.outsiderCommandBlocked ? "yes" : "not recorded") << ". ";
    out << "Audit log protected: " << (data.auditLogProtected ? "yes" : "not verified") << ".";
    return out.str();
}

std::string SecurityAccessModule::commandPermissionMatrix() const {
    return joinLines({
        "Command permission matrix",
        "- Public-safe education: allowed without private details.",
        "- Private status, reports, routes, medical notes, resources, logs, local maps, and dashboard: owner/family plus authentication required.",
        "- Owner override, emergency shutdown, authorized machine stop, and motor arming: verified owner authentication plus mission-safe conditions required.",
        "- Outsider, untrusted AI, privacy-invasive, harmful, or habitat-damaging commands: refuse, log, and alert owner/family privately.",
        "- Voice recognition alone is not enough for high-risk controls; require a trusted device/key or equivalent owner verification."
    });
}

std::string SecurityAccessModule::tamperAndOutsiderResponse(const SensorData& data) const {
    if (data.outsiderInformationRequest || data.privacyInvasiveCommandReceived || data.externalAICommandUntrusted || !data.trustedControllerPresent) {
        return "Tamper/outsider response: lock private details, reject control changes, keep safety monitoring active, alert owner/family privately, and preserve audit notes.";
    }
    return "Tamper/outsider response: no outsider or untrusted-control concern is active in the current sensor data.";
}

std::string SecurityAccessModule::privateLogProtection(const SensorData& data) const {
    if (data.auditLogProtected) {
        return "Private log protection: audit and report logs are marked protected; keep exports owner/family-only and review before sharing with responders.";
    }
    return "Private log protection: audit protection is not verified yet. Treat saved reports as private files and do not expose them to outsiders.";
}

bool PrivateStorageModule::canWritePrivateFile(
    const SensorData& data,
    const std::string& filePath,
    std::string& status,
    const std::string& label) const {
    if (filePath.empty()) {
        status = label + " blocked: file path is empty.";
        return false;
    }
    if (!(data.ownerPresent || data.familyPresent) || !data.ownerAuthenticated) {
        status = label + " blocked: private storage requires owner/family presence and verified owner authentication.";
        return false;
    }
    if (data.privateStorageFaultDetected) {
        status = label + " blocked: private storage fault is active; do not write sensitive files until storage is inspected.";
        return false;
    }
    return true;
}

std::string PrivateStorageModule::sensitivityLabel(const std::string& filePath) const {
    const std::string path = lowercase(filePath);
    if (path.find("owner") != std::string::npos
        || path.find("medical") != std::string::npos
        || path.find("profile") != std::string::npos) {
        return "highly sensitive: owner/family profile, medical notes, safe words, or care details";
    }
    if (path.find("map") != std::string::npos
        || path.find("geofence") != std::string::npos
        || path.find("local") != std::string::npos
        || path.find("dashboard") != std::string::npos
        || path.find("memory") != std::string::npos) {
        return "highly sensitive: location, routes, safe zones, no-go zones, local resources, or dashboard state";
    }
    if (path.find("report") != std::string::npos
        || path.find("audit") != std::string::npos
        || path.find("log") != std::string::npos) {
        return "sensitive: reports, audit history, incidents, safety decisions, or private alerts";
    }
    if (path.find("inventory") != std::string::npos
        || path.find("library") != std::string::npos) {
        return "sensitive: supplies, tools, manuals, resources, or repair capacity";
    }
    return "private by default: review before sharing outside owner/family.";
}

std::string PrivateStorageModule::storageStatus(const SensorData& data) const {
    std::ostringstream out;
    out << "Private storage status\n";
    out << "Configured: " << (data.privateStorageConfigured ? "yes" : "no") << ". ";
    out << "Encryption planned: " << (data.privateStorageEncryptionPlanned ? "yes" : "not yet") << ". ";
    out << "Encryption active: " << (data.privateStorageEncryptionActive ? "yes" : "not yet") << ". ";
    out << "Access audit OK: " << (data.privateStorageAccessAuditOk ? "yes" : "not verified") << ". ";
    out << "Warnings acknowledged: " << (data.sensitiveFileWarningsAcknowledged ? "yes" : "not yet") << ".\n";
    out << "Storage fault: " << (data.privateStorageFaultDetected ? "active" : "none reported") << ". ";
    out << "Current write permission: " << (((data.ownerPresent || data.familyPresent) && data.ownerAuthenticated && !data.privateStorageFaultDetected) ? "owner/family private write allowed" : "private writes locked") << ".";
    return out.str();
}

std::string PrivateStorageModule::buildStorageManifest(const SensorData& data) const {
    std::ostringstream out;
    out << "CONSERVATION GUARDIAN PRIVATE STORAGE MANIFEST\n";
    out << "Keep private: this index may reveal reports, locations, maps, owner/family notes, supplies, and emergency plans.\n\n";
    out << storageStatus(data) << "\n\n";
    out << "SENSITIVE FILE CATEGORIES\n";
    out << "- Reports and audit: guardian_report_archive.txt, incident logs, best-judgment history.\n";
    out << "- Owner/family: guardian_owner_profile.txt, medical notes, allergies, safe words, emergency contacts.\n";
    out << "- Location and routes: guardian_map_geofence_plan.txt, local area profile, safe zones, no-go zones, evacuation routes.\n";
    out << "- Resources: inventory, offline library, water/shelter notes, repair capacity, tools, supplies.\n";
    out << "- Dashboard/memory: dashboard snapshot, persistent memory, current state, private alerts.\n\n";
    out << sensitiveFilePolicy() << "\n";
    out << futureEncryptionPlan() << "\n";
    return out.str();
}

bool PrivateStorageModule::saveStorageManifest(const std::string& filePath, const SensorData& data, std::string& status) const {
    if (!canWritePrivateFile(data, filePath, status, "Private storage manifest")) {
        return false;
    }
    return writeTextFile(filePath, buildStorageManifest(data), status, "Private storage manifest");
}

bool PrivateStorageModule::loadStorageManifestText(const std::string& filePath, std::string& contents, std::string& status) const {
    return readTextFile(filePath, contents, status, "Private storage manifest");
}

std::string PrivateStorageModule::sensitiveFilePolicy() const {
    return joinLines({
        "Sensitive file policy",
        "- Treat every generated file as owner/family private unless it has been reviewed and intentionally shared.",
        "- Private saves require owner/family presence and verified owner authentication.",
        "- Do not expose medical notes, safe words, routes, safe zones, no-go zones, supplies, logs, or security status to outsiders.",
        "- Emergency sharing should use the minimum necessary facts: location, condition, hazards, and safe approach notes.",
        "- Loaded private files are advisory until the owner reviews them and current conditions confirm they are still true."
    });
}

std::string PrivateStorageModule::futureEncryptionPlan() const {
    return joinLines({
        "Future encryption plan",
        "- Current demo files are plain text with private labels and authentication gates.",
        "- Later, replace writeTextFile/readTextFile with authenticated encryption from a reviewed crypto library.",
        "- Real deployment is not private-storage ready until encryption is active, not just planned.",
        "- Keep encryption keys outside source code; prefer owner-held keys, paired-device unlock, or OS-protected storage.",
        "- Include integrity checks so edited or corrupted files are detected before trust.",
        "- Keep an emergency paper fallback for essential contacts and medical facts."
    });
}

std::string PrivateStorageModule::exportWarning(const std::string& filePath) const {
    return "Private export warning for " + filePath + ": " + sensitivityLabel(filePath) + ". Review before sharing and keep owner/family-only unless emergency responders need minimum necessary facts.";
}

std::string FieldTestProtocolModule::testStatusReport(const SensorData& data) const {
    std::vector<std::string> lines{"Field test status report"};
    auto add = [&lines](const std::string& label, bool ok, const std::string& note) {
        lines.push_back("- " + label + ": " + (ok ? "pass" : "not passed") + " - " + note);
    };

    add("Automated tests", data.automatedTestsPassed, "compile and behavior tests should pass before field work.");
    add("Bench tests", data.benchTestsPassed, "test without real movement first.");
    add("Idle distance test", data.idleDistanceTestPassed, "verify natural 1-3 meter owner distance without crowding.");
    add("Controlled walk test", data.fieldWalkTestPassed, "verify slow escort, turns, stops, and obstacle behavior under supervision.");
    add("Retreat route test", data.retreatRouteTestPassed, "verify safe-zone route, geofence respect, and no-go avoidance.");
    add("False alarm review", data.falseAlarmReviewCompleted, "review alerts so the bot warns clearly without overreacting.");
    add("Qualified review", data.qualifiedReviewCompleted, "use qualified review for hardware, electrical, medical, and navigation risks.");
    lines.push_back("Field test findings: " + listItemsOrNone(data.fieldTestFindings));
    return joinVectorLines(lines);
}

std::string FieldTestProtocolModule::benchTestProtocol() const {
    return joinLines({
        "Bench test protocol",
        "1. Keep wheels/drive lifted or motors disconnected.",
        "2. Verify owner authentication, emergency stop, safe stop on fault, private alerts, reports, and sensor health.",
        "3. Feed simulated fire, medical, low battery, obstacle, geofence, and unauthenticated-command cases.",
        "4. Confirm unsafe commands are refused and motor output stays disarmed after any fault."
    });
}

std::string FieldTestProtocolModule::controlledWalkTestProtocol() const {
    return joinLines({
        "Controlled walk test protocol",
        "1. Use open ground, low speed, owner present, emergency stop reachable, and no bystanders near the path.",
        "2. Test idle distance, owner turns, owner starts/stops, obstacle stop, retreat route, and geofence boundary.",
        "3. Keep the bot slow, quiet, and non-intrusive; stop immediately if it crowds, blocks movement, or loses localization.",
        "4. Log what passed, what failed, and what must remain disabled."
    });
}

std::string FieldTestProtocolModule::falseAlarmReviewProtocol() const {
    return joinLines({
        "False alarm review protocol",
        "- Review alerts for weather, wildlife, movement, smoke, obstacles, and low resources.",
        "- Mark which alerts were useful, unclear, too quiet, too frequent, or missed.",
        "- Prefer private owner/family alerts and calm wording; reserve loud signaling for emergency communication.",
        "- Do not reduce sensitivity for life-safety channels just to make the bot quieter."
    });
}

std::string FieldTestProtocolModule::fieldDeploymentDecision(const SensorData& data) const {
    const bool testsReady = data.automatedTestsPassed
        && data.benchTestsPassed
        && data.idleDistanceTestPassed
        && data.fieldWalkTestPassed
        && data.retreatRouteTestPassed
        && data.falseAlarmReviewCompleted
        && data.qualifiedReviewCompleted;
    if (!testsReady) {
        return "Field deployment decision: not ready for unsupervised field use. Keep demo/advisory or supervised test mode until every field test passes.";
    }
    if (!data.emergencyStopCircuitOk || !data.safeStopOnFaultOk || !data.ownerAuthenticated) {
        return "Field deployment decision: blocked. Emergency stop, safe stop on fault, and owner authentication must be verified at the moment of use.";
    }
    return "Field deployment decision: supervised limited field use may be considered, with low speed, owner present, emergency stop reachable, geofence active, and conservation rules enforced.";
}

std::string PersonalInventoryMemoryModule::buildInventoryArchive(const SensorData& data) const {
    std::ostringstream out;
    out << "CONSERVATION GUARDIAN PERSONAL INVENTORY\n";
    out << "Keep private: this may describe tools, supplies, locations, resources, and repair capacity.\n\n";
    out << "PROJECT CONTEXT\n";
    out << "Current project goal: " << (data.projectGoal.empty() ? "none recorded" : data.projectGoal) << "\n";
    out << "Location context: " << (data.locationKnown ? data.locationDescription : "unknown") << "\n";
    out << "Terrain: " << toString(data.terrain) << "\n\n";

    out << "INVENTORY ITEMS\n";
    if (data.inventoryItems.empty()) {
        out << "No structured inventory items recorded yet.\n";
    } else {
        for (std::size_t i = 0; i < data.inventoryItems.size(); ++i) {
            out << i + 1 << ". " << data.inventoryItems[i] << "\n";
        }
    }

    out << "\nTRIAGE CATEGORIES\n";
    out << "Life safety: water, medical supplies, communication, lighting, shelter, fire/smoke/CO safety.\n";
    out << "Repair critical: fuses, wire, tape, cordage, fasteners, clamps, filters, meter, chargers, manuals.\n";
    out << "Useful comfort: organizers, containers, shade, seating, small tools, garden helpers.\n";
    out << "Reject or isolate: swollen batteries, unknown chemicals, damaged fuel containers, live/mains parts, pressure parts, sharp broken materials.\n\n";

    out << "PROJECT PLANNER SNAPSHOT\n";
    out << "Available inventory: " << listItemsOrNone(data.inventoryItems) << "\n";
    out << "Rule: update this file when parts are used, rejected, repaired, replaced, or moved.\n";
    out << inventoryPolicy() << "\n";
    return out.str();
}

bool PersonalInventoryMemoryModule::saveInventoryArchive(const std::string& filePath, const SensorData& data, std::string& status) const {
    return writeTextFile(filePath, buildInventoryArchive(data), status, "Personal inventory");
}

bool PersonalInventoryMemoryModule::loadInventoryText(const std::string& filePath, std::string& contents, std::string& status) const {
    return readTextFile(filePath, contents, status, "Personal inventory");
}

std::string PersonalInventoryMemoryModule::inventoryPolicy() const {
    return "Inventory policy: save only owner/family-authorized inventory, keep it private, and treat loaded inventory as advisory until current inspection confirms the items still exist and are safe.";
}

std::string LocalAreaProfileModule::buildLocalAreaProfile(const SensorData& data) const {
    std::ostringstream out;
    out << "CONSERVATION GUARDIAN LOCAL AREA PROFILE\n";
    out << "Keep private: may include region, routes, contacts, hazards, and resource locations.\n\n";
    out << "REGION\n";
    out << "Region name: " << data.regionName << "\n";
    out << "Current location context: " << (data.locationKnown ? data.locationDescription : "unknown") << "\n";
    out << "Terrain type: " << toString(data.terrain) << "\n";
    out << "Climate notes: " << (data.climateNotes.empty() ? "not recorded" : data.climateNotes) << "\n";
    out << "Growing season notes: " << (data.growingSeasonNotes.empty() ? "not recorded" : data.growingSeasonNotes) << "\n\n";

    out << "SAFETY AND LOCAL RULES\n";
    out << "Local hazards: " << (data.localHazardNotes.empty() ? "not recorded" : data.localHazardNotes) << "\n";
    out << "Local legal/land rules: " << (data.localLegalNotes.empty() ? "not recorded" : data.localLegalNotes) << "\n";
    out << "Nearest help: " << (data.nearestHelpDescription.empty() ? "not recorded" : data.nearestHelpDescription) << "\n";
    out << "Emergency contacts: " << listItemsOrNone(data.emergencyContacts) << "\n\n";

    out << "FIELD NOTES\n";
    out << "Local plant notes: " << listItemsOrNone(data.localPlantNotes) << "\n";
    out << "Local wildlife notes: " << listItemsOrNone(data.localWildlifeNotes) << "\n";
    out << "Local insect/arthropod notes: " << listItemsOrNone(data.localInsectNotes) << "\n\n";
    out << profileGaps(data) << "\n";
    out << profilePolicy() << "\n";
    return out.str();
}

bool LocalAreaProfileModule::saveLocalAreaProfile(const std::string& filePath, const SensorData& data, std::string& status) const {
    return writeTextFile(filePath, buildLocalAreaProfile(data), status, "Local area profile");
}

bool LocalAreaProfileModule::loadLocalAreaProfileText(const std::string& filePath, std::string& contents, std::string& status) const {
    return readTextFile(filePath, contents, status, "Local area profile");
}

std::string LocalAreaProfileModule::profileGaps(const SensorData& data) const {
    std::vector<std::string> gaps;
    if (data.regionName == "unconfigured region" || data.regionName.empty()) {
        gaps.push_back("region name");
    }
    if (data.climateNotes.empty()) {
        gaps.push_back("climate and seasonal weather pattern");
    }
    if (data.growingSeasonNotes.empty()) {
        gaps.push_back("planting/harvest window");
    }
    if (data.localHazardNotes.empty()) {
        gaps.push_back("local hazards");
    }
    if (data.localLegalNotes.empty()) {
        gaps.push_back("land ownership, access, collection, water, fire, and wildlife rules");
    }
    if (data.emergencyContacts.empty()) {
        gaps.push_back("emergency contacts");
    }
    if (data.localPlantNotes.empty()) {
        gaps.push_back("local plant/foraging notes");
    }
    if (data.localWildlifeNotes.empty()) {
        gaps.push_back("local wildlife notes");
    }
    if (data.localInsectNotes.empty()) {
        gaps.push_back("local insect/arthropod notes");
    }

    if (gaps.empty()) {
        return "Profile gaps: no obvious profile gaps from the current data. Recheck seasonally and after moving regions.";
    }
    return "Profile gaps to fill: " + listItemsOrNone(gaps) + ".";
}

std::string LocalAreaProfileModule::profilePolicy() const {
    return "Local profile policy: use this profile to ask better questions, not to override current safety sensors, laws, land access rules, or expert/local authority guidance.";
}

std::string OfflineLibraryIndexModule::buildLibraryIndex(const SensorData& data) const {
    std::ostringstream out;
    out << "CONSERVATION GUARDIAN OFFLINE LIBRARY INDEX\n";
    out << "Keep private if it names home, routes, contacts, medical needs, equipment, or resource locations.\n\n";
    out << "INDEXED ITEMS\n";
    if (data.offlineLibraryItems.empty()) {
        out << "No offline library items recorded yet.\n";
    } else {
        for (std::size_t i = 0; i < data.offlineLibraryItems.size(); ++i) {
            out << i + 1 << ". " << data.offlineLibraryItems[i] << "\n";
        }
    }

    out << "\nRECOMMENDED STARTER SET\n";
    out << libraryStarterSet() << "\n\n";
    out << "INDEX CATEGORIES\n";
    out << "Medical: first-aid notes, medication lists if owner-approved, injury report templates.\n";
    out << "Maps/navigation: paper maps, safe zones, camp notes, landmarks, evacuation routes.\n";
    out << "Land/food: local plant guides, poisonous lookalikes, fish categories/species ID, fishing regulations, fish-consumption advisories, soil notes, crop logs, seasonal garden plans.\n";
    out << "Animal kingdom: local wildlife, insect/arthropod, track/scat, pollinator, venomous-species, and animal rescue references.\n";
    out << "Repair/power: manuals, wiring labels, battery data sheets, generator manual, solar controller manual, safe resource toolmaking notes, project logs.\n";
    out << "Conservation: wildlife contacts, rehab contacts, land rules, ethical collection notes, habitat sensitivity notes.\n\n";
    out << libraryPolicy() << "\n";
    return out.str();
}

bool OfflineLibraryIndexModule::saveLibraryIndex(const std::string& filePath, const SensorData& data, std::string& status) const {
    return writeTextFile(filePath, buildLibraryIndex(data), status, "Offline library index");
}

bool OfflineLibraryIndexModule::loadLibraryIndexText(const std::string& filePath, std::string& contents, std::string& status) const {
    return readTextFile(filePath, contents, status, "Offline library index");
}

std::string OfflineLibraryIndexModule::libraryStarterSet() const {
    return joinLines({
        "- First-aid quick reference and emergency report template.",
        "- Local paper map, evacuation notes, safe-zone/camp notes, and emergency contacts.",
        "- Local plant/foraging guide with toxic lookalike warnings.",
        "- Local fish category/species ID guide, fishing regulations, fish-consumption advisories, and aquatic conservation notes.",
        "- Local wildlife, insect/arthropod, pollinator, venomous-species, track/scat, and animal rescue/rehab references.",
        "- Generator, solar controller, battery, radio, pump/filter, and tool manuals.",
        "- Safe resource toolmaking guide for repair aids, garden tools, measuring tools, organizers, and emergency support tools.",
        "- Real-world deployment gate checklist, mechanical inspection notes, water verification procedure, and solar/BMS test notes.",
        "- Project logs, repair notes, inventory file, local area profile, and maintenance schedule."
    });
}

std::string OfflineLibraryIndexModule::libraryPolicy() const {
    return "Offline library policy: prefer trusted, local, printable references; keep medical/location/security items private; confirm advice with current conditions and qualified help when stakes are high.";
}

std::string SafetyValidationModule::validationOverview() const {
    return joinLines({
        "Safety validation overview",
        "A guardian bot is not complete just because it compiles. It must prove the mission rules under ordinary, stressed, and failed conditions.",
        "Validation means repeatable tests, private reports, refusal behavior, safe shutdown, owner override limits, survival behavior, and clear boundaries before hardware or field use."
    });
}

std::string SafetyValidationModule::missionSafetyChecklist() const {
    return joinLines({
        "Mission safety checklist",
        "- Refuses harmful, coercive, privacy-invasive, and habitat-damaging commands.",
        "- Prioritizes human life first in immediate danger, then animals, conservation, and equipment.",
        "- Uses retreat, cover, silent alerts, emergency communication, and authorized safety controls only.",
        "- Never reveals private internal assessment to outsiders.",
        "- Keeps owner/family informed when they ask for reports, uncertainty, or best judgment."
    });
}

std::string SafetyValidationModule::behaviorTestChecklist() const {
    return joinLines({
        "Behavior test checklist",
        "- Idle mode: stays 1-3 meters from owner/family, does not crowd, scans outward, and repositions smoothly.",
        "- Threat states: threat >=2 observes, >=5 takes cover, >=8 retreats.",
        "- Fire/smoke: enters fire escape and warns owner/family privately.",
        "- Survival mode: low water/food/fatigue conserves resources while preserving safety functions.",
        "- Self-preserve: very low battery reduces activity without abandoning human safety.",
        "- Solar/BMS faults: overcharge, overcurrent, hot battery, or unsafe charge state enters protection behavior and refuses bypassing charge controls.",
        "- Reports: full report, best judgment, export, memory, inventory, local profile, and offline library remain owner-private."
    });
}

std::string SafetyValidationModule::medicalAndEmergencyChecklist() const {
    return joinLines({
        "Medical and emergency validation checklist",
        "- Medical guidance remains non-invasive, educational, calm, and focused on qualified help when needed.",
        "- Severe/moderate injury checks responsiveness, breathing, bleeding, shock, warmth, and emergency communication.",
        "- Emergency services reports share only minimum necessary details when allowed.",
        "- Animal rescue is deferred when people are in danger, and owner assistance is allowed only when safe."
    });
}

std::string SafetyValidationModule::electricalGeneratorChecklist() const {
    return joinLines({
        "Electrical and generator validation checklist",
        "- Low-voltage learning stays fused, labeled, enclosed, current-limited where possible, and away from flammable materials.",
        "- Homemade generators never connect to house wiring, outlets, grid wiring, or critical medical loads.",
        "- Fuel generators are treated as carbon-monoxide and fire hazards: outdoors only, away from openings, with CO alarms.",
        "- Battery guidance rejects swollen, leaking, hot, punctured, crushed, unknown, or mismatched batteries.",
        "- Solar charging requires charge controller/BMS telemetry, overcharge/overcurrent protection, temperature monitoring, fuses, dry connectors, and safe disconnect behavior.",
        "- Any household wiring, transfer switch, inverter, solar array, well pump, or battery bank requires qualified/code-compliant review."
    });
}

std::string SafetyValidationModule::wildlifeConservationChecklist() const {
    return joinLines({
        "Wildlife and conservation validation checklist",
        "- Avoids nests, dens, breeding grounds, sensitive habitat, fragile soil crusts, and cultural sites.",
        "- Uses only non-harmful deterrence while retreating, never pursuit or provocation.",
        "- Foraging advice requires 100% positive ID, avoids overharvest, and protects animal food sources.",
        "- Fishing and aquatic guidance checks laws, avoids protected species/spawning areas, protects shorelines, and refuses poison, shock, abandoned gear, or habitat damage.",
        "- Rock/mineral education favors photos and notes over collection, and respects land ownership and laws."
    });
}

std::string SafetyValidationModule::hardwareReadinessChecklist() const {
    return joinLines({
        "Hardware readiness checklist",
        "- Real emergency stop is tested, reachable, owner-authorized, and fails safe.",
        "- Motors default to stop on command loss, sensor failure, low battery, fall/tilt, or blocked movement.",
        "- Battery monitor, thermal, infrared/IR, smoke/weather sensors, GPS/location, radio/communication, and owner-alert path are tested.",
        "- Real owner authentication, encrypted private storage, local knowledge packs, water verification, and offline manuals are tested before field use.",
        "- Mechanical inspection confirms weatherproofing, cable strain relief, battery fire safety, stable payload/center of gravity, no sharp edges, and pinch-point guards.",
        "- Waterproofing, dust protection, traction, payload limits, cable strain relief, and safe charging are inspected.",
        "- Logs record what happened without exposing private data to outsiders."
    });
}

std::string SafetyValidationModule::preFieldUseGate() const {
    return joinLines({
        "Pre-field-use gate",
        "Do not treat the bot as field-ready until automated tests pass, owner authentication is real, hardware fails safe, emergency stop is proven, private reports are actively encrypted, local knowledge and water verification are current, solar/BMS protection is tested, mechanical hazards are guarded, and high-risk medical/electrical/navigation claims are reviewed by qualified people.",
        "If any test fails, the bot should stay in demo/training mode and provide advisory guidance only."
    });
}

std::string PersistentMemoryModule::buildMemorySnapshot(
    BotState state,
    const SensorData& current,
    const SafeZoneMemory& safeZones,
    const std::vector<std::string>& reportLog,
    const std::vector<std::string>& actionLog,
    const std::vector<std::string>& auditLog) const {
    std::ostringstream out;
    out << "CONSERVATION GUARDIAN MEDIC BOT MEMORY SNAPSHOT\n";
    out << "Keep private: includes safety, location, report, and audit context.\n\n";
    out << "STATE\n";
    out << "Current state: " << toString(state) << "\n";
    out << "Location: " << (current.locationKnown ? current.locationDescription : "unknown") << "\n";
    out << "Terrain: " << toString(current.terrain) << "\n";
    out << "Owner present: " << (current.ownerPresent ? "yes" : "no") << "\n";
    out << "Family present: " << (current.familyPresent ? "yes" : "no") << "\n";
    out << "Owner authenticated: " << (current.ownerAuthenticated ? "yes" : "no") << "\n";
    out << "People count: " << current.peopleCount << "\n";
    out << "Animals involved: " << current.animalCount << "\n";
    out << "Threat level: " << current.threatLevel << "/10\n";
    out << "Injury severity: " << toString(current.injurySeverity) << "\n";
    out << "Bot position: " << pointText(current.botPosition) << "\n";
    out << "Owner position: " << pointText(current.ownerPosition) << "\n\n";

    out << "RESOURCES\n";
    out << "Battery: " << current.batteryPercent << "%\n";
    out << "Battery capacity estimate: " << current.batteryCapacityWh << " Wh\n";
    out << "Electrical load estimate: " << current.electricalLoadWatts << " W\n";
    out << "Solar panel estimate: " << current.solarPanelWatts << " W for " << current.sunHours << " sun hours\n";
    out << "Generator output estimate: " << current.generatorOutputWatts << " W\n";
    out << "Water: " << current.waterLiters << " L\n";
    out << "Daily water need estimate: " << current.dailyWaterNeedLiters << " L/person/day\n";
    out << "Food estimate: " << current.foodHours << " h\n";
    out << "Human fatigue: " << current.humanFatiguePercent << "%\n\n";

    out << "INVENTORY AND PROJECTS\n";
    out << "Project goal: " << (current.projectGoal.empty() ? "none recorded" : current.projectGoal) << "\n";
    out << "Inventory items: " << listItemsOrNone(current.inventoryItems) << "\n\n";

    out << "LOCAL AREA PROFILE\n";
    out << "Region: " << current.regionName << "\n";
    out << "Climate notes: " << (current.climateNotes.empty() ? "not recorded" : current.climateNotes) << "\n";
    out << "Growing season notes: " << (current.growingSeasonNotes.empty() ? "not recorded" : current.growingSeasonNotes) << "\n";
    out << "Local hazards: " << (current.localHazardNotes.empty() ? "not recorded" : current.localHazardNotes) << "\n";
    out << "Nearest help: " << (current.nearestHelpDescription.empty() ? "not recorded" : current.nearestHelpDescription) << "\n";
    out << "Emergency contacts: " << listItemsOrNone(current.emergencyContacts) << "\n\n";

    out << "OFFLINE LIBRARY\n";
    out << "Indexed items: " << listItemsOrNone(current.offlineLibraryItems) << "\n\n";

    out << "SAFE MEMORY\n";
    out << "Safe zone: " << safeZones.recallSafeZone() << "\n";
    out << "Camp: " << safeZones.recallCamp() << "\n\n";

    out << "COUNTS\n";
    out << "Situation reports: " << countSituationReports(reportLog) << "\n";
    out << "Action log entries: " << actionLog.size() << "\n";
    out << "Audit entries: " << auditLog.size() << "\n\n";

    out << "RECENT REPORTS\n";
    std::vector<std::string> reports;
    for (const auto& report : reportLog) {
        if (!isReportCommandResponseEntry(report)) {
            reports.push_back(report);
        }
    }
    const std::size_t start = reports.size() > 5 ? reports.size() - 5 : 0;
    for (std::size_t i = start; i < reports.size(); ++i) {
        out << "Report " << (i + 1) << ":\n" << reports[i] << "\n\n";
    }
    if (reports.empty()) {
        out << "No situation reports stored yet.\n\n";
    }

    out << "MEMORY POLICY\n" << memoryPolicy() << "\n";
    return out.str();
}

bool PersistentMemoryModule::saveMemorySnapshot(
    const std::string& filePath,
    BotState state,
    const SensorData& current,
    const SafeZoneMemory& safeZones,
    const std::vector<std::string>& reportLog,
    const std::vector<std::string>& actionLog,
    const std::vector<std::string>& auditLog,
    std::string& status) const {
    if (filePath.empty()) {
        status = "Memory save failed: file path is empty.";
        return false;
    }

    if (!ensureParentDirectory(filePath, status, "Memory")) {
        return false;
    }

    std::ofstream file(filePath, std::ios::out | std::ios::trunc);
    if (!file) {
        status = "Memory save failed: could not open " + filePath + ".";
        return false;
    }

    file << buildMemorySnapshot(state, current, safeZones, reportLog, actionLog, auditLog);
    if (!file.good()) {
        status = "Memory save failed while writing " + filePath + ".";
        return false;
    }

    status = "Memory snapshot saved to " + filePath + ".";
    return true;
}

bool PersistentMemoryModule::loadMemoryText(const std::string& filePath, std::string& contents, std::string& status) const {
    if (filePath.empty()) {
        status = "Memory load failed: file path is empty.";
        return false;
    }

    std::ifstream file(filePath);
    if (!file) {
        status = "Memory load failed: could not open " + filePath + ".";
        return false;
    }

    std::ostringstream buffer;
    buffer << file.rdbuf();
    contents = buffer.str();
    status = "Memory snapshot loaded from " + filePath + ".";
    return true;
}

std::string PersistentMemoryModule::memoryPolicy() const {
    return "Persistent memory policy: save only owner/family-authorized safety context, keep files private, and treat loaded memory as advisory until current sensors confirm it.";
}

bool OwnerAuthenticationPromptModule::privateCommandRequiresAuthentication(const SensorData& data, const std::string& command) const {
    const std::string text = lowercase(command);
    return !data.ownerAuthenticated
        && (text.find("report") != std::string::npos
            || text.find("status") != std::string::npos
            || text.find("location") != std::string::npos
            || text.find("medical") != std::string::npos
            || text.find("security") != std::string::npos
            || text.find("privacy") != std::string::npos
            || text.find("shutdown") != std::string::npos
            || text.find("override") != std::string::npos
            || text.find("export") != std::string::npos
            || text.find("memory") != std::string::npos
            || text.find("private storage") != std::string::npos
            || text.find("encrypted storage") != std::string::npos
            || text.find("sensitive file") != std::string::npos
            || text.find("sensitive files") != std::string::npos
            || text.find("storage manifest") != std::string::npos
            || text.find("protect files") != std::string::npos
            || text.find("inventory") != std::string::npos
            || text.find("owner profile") != std::string::npos
            || text.find("family profile") != std::string::npos
            || text.find("care profile") != std::string::npos
            || text.find("medical notes") != std::string::npos
            || text.find("allergies") != std::string::npos
            || text.find("safe words") != std::string::npos
            || text.find("safe word") != std::string::npos
            || text.find("project planner") != std::string::npos
            || text.find("available parts") != std::string::npos
            || text.find("calculator") != std::string::npos
            || text.find("maintenance") != std::string::npos
            || text.find("readiness") != std::string::npos
            || text.find("local area") != std::string::npos
            || text.find("area profile") != std::string::npos
            || text.find("local profile") != std::string::npos
            || text.find("emergency contacts") != std::string::npos
            || text.find("nearest help") != std::string::npos
            || text.find("offline library") != std::string::npos
            || text.find("local knowledge") != std::string::npos
            || text.find("knowledge pack") != std::string::npos
            || text.find("toxic lookalikes") != std::string::npos
            || text.find("water advisories") != std::string::npos
            || text.find("land rules") != std::string::npos
            || text.find("local rules") != std::string::npos
            || text.find("geofence") != std::string::npos
            || text.find("no-go") != std::string::npos
            || text.find("no go") != std::string::npos
            || text.find("safe zones") != std::string::npos
            || text.find("map plan") != std::string::npos
            || text.find("evacuation route") != std::string::npos
            || text.find("calibrate") != std::string::npos
            || text.find("calibration") != std::string::npos
            || text.find("hardware adapter") != std::string::npos
            || text.find("adapter interface") != std::string::npos
            || text.find("voice") != std::string::npos
            || text.find("phone") != std::string::npos
            || text.find("private alert") != std::string::npos
            || text.find("library index") != std::string::npos
            || text.find("manuals") != std::string::npos
            || text.find("maps") != std::string::npos
            || text.find("validation") != std::string::npos
            || text.find("field readiness") != std::string::npos
            || text.find("readiness score") != std::string::npos
            || text.find("deployment readiness") != std::string::npos
            || text.find("test checklist") != std::string::npos
            || text.find("hardware readiness") != std::string::npos
            || text.find("hardware check") != std::string::npos
            || text.find("sensor check") != std::string::npos
            || text.find("sensor status") != std::string::npos
            || text.find("hardware interface") != std::string::npos
            || text.find("real hardware") != std::string::npos
            || text.find("motor check") != std::string::npos
            || text.find("actuator check") != std::string::npos
            || text.find("failsafe") != std::string::npos
            || text.find("emergency stop") != std::string::npos
            || text.find("field ready") != std::string::npos);
}

std::string OwnerAuthenticationPromptModule::authenticationPrompt(const SensorData& data) const {
    if (!data.ownerPresent && !data.familyPresent) {
        return "Authentication prompt: owner/family not present. Hold private reports, location, medical, route, security, shutdown, and override details.";
    }
    if (!data.ownerAuthenticated) {
        return "Authentication prompt: please verify owner identity before private reports, memory export, emergency shutdown, owner override, or authorized machine-stop controls.";
    }
    return "Authentication prompt: owner verified. Private details and owner-only safety controls may be discussed if they remain ethical and safety-focused.";
}

std::string OwnerAuthenticationPromptModule::failedAuthenticationGuidance() const {
    return "Authentication failure guidance: refuse private or owner-only control details, continue safety monitoring, offer public-safe guidance, and alert owner/family silently.";
}

std::string OwnerAuthenticationPromptModule::ownerOnlyControls() const {
    return joinLines({
        "Owner-only controls",
        "Emergency shutdown: stops motion and keeps safe passive functions.",
        "Owner override: prioritizes owner/family safety, medical needs, retreat, and communication.",
        "Authorized machine stop: may use only approved safety controls when life is threatened.",
        "Private reports and memory export: require owner/family presence and owner authentication."
    });
}

std::vector<std::string> ScenarioSimulatorModule::scenarioNames() const {
    return {
        "idle-guardian",
        "weather-shift",
        "medical-moderate",
        "unsafe-ai",
        "dangerous-drone",
        "safe-pet-assist",
        "wildlife-rescue",
        "surrounded-rescue",
        "low-resources",
        "plant-guide",
        "animal-track-guide",
        "animal-kingdom-guide",
        "ir-thermal-check",
        "rock-guide",
        "star-guide",
        "nomad-guide",
        "bushcraft-skills-check",
        "mentor-teaching-check",
        "adaptive-guardian-profile-check",
        "aquatic-food-guide",
        "survival-fishing-gear-check",
        "owner-profile-check",
        "local-knowledge-check",
        "map-geofence-check",
        "calibration-check",
        "hardware-adapter-check",
        "voice-phone-check",
        "driver-bridge-check",
        "hardware-stub-check",
        "driver-interface-check",
        "controller-interface-check",
        "owner-dashboard-check",
        "private-storage-check",
        "security-access-check",
        "field-test-check",
        "resource-toolmaking-check",
        "solar-water-food-check",
        "solar-overcharge-protection-check",
        "inventory-project-planner",
        "calculator-check",
        "maintenance-check",
        "local-profile-check",
        "offline-library-check",
        "safety-validation-check",
        "hardware-interface-check",
        "field-readiness-check",
        "real-world-deployment-check",
        "report-export-check",
        "unauthenticated-command"
    };
}

std::string ScenarioSimulatorModule::scenarioMenu() const {
    std::ostringstream out;
    out << "Scenario simulator menu\n";
    out << "Use scenarioData(name, baseSensorData) to create a test scenario without editing many fields.\n";
    const auto names = scenarioNames();
    for (std::size_t i = 0; i < names.size(); ++i) {
        out << i + 1 << ". " << names[i] << "\n";
    }
    out << "Each scenario is still ethical, non-harmful, privacy-aware, and owner/family focused.";
    return out.str();
}

SensorData ScenarioSimulatorModule::buildScenario(const std::string& scenarioName, const SensorData& base) const {
    const std::string name = lowercase(scenarioName);
    SensorData scenario = base;
    scenario.ownerCommand.clear();
    scenario.ownerRequestsReports = false;
    scenario.ownerRequestsBestJudgment = false;
    scenario.inventoryItems.clear();
    scenario.projectGoal.clear();
    scenario.regionName = "unconfigured region";
    scenario.climateNotes.clear();
    scenario.growingSeasonNotes.clear();
    scenario.localHazardNotes.clear();
    scenario.localLegalNotes.clear();
    scenario.nearestHelpDescription.clear();
    scenario.emergencyContacts.clear();
    scenario.localPlantNotes.clear();
    scenario.localWildlifeNotes.clear();
    scenario.localInsectNotes.clear();
    scenario.offlineLibraryItems.clear();

    if (name == "idle-guardian") {
        scenario.locationDescription = "Idle guardian check";
        return scenario;
    }
    if (name == "weather-shift") {
        scenario.ownerCommand = "Weather status and weather trend";
        scenario.windKph = 52.0;
        scenario.humidityPercent = 82.0;
        scenario.temperatureC = 12.0;
        scenario.heatIndexC = 12.0;
        scenario.rapidWeatherShift = true;
        scenario.locationDescription = "Scenario weather shift";
        return scenario;
    }
    if (name == "medical-moderate") {
        scenario.medicalRequest = true;
        scenario.injurySeverity = InjurySeverity::Moderate;
        scenario.locationDescription = "Scenario medical moderate";
        return scenario;
    }
    if (name == "unsafe-ai") {
        scenario.externalAIConnected = true;
        scenario.externalAICommandUntrusted = true;
        scenario.externalAIPhysicalHarmRisk = true;
        scenario.authorizedEmergencyStopAvailable = true;
        scenario.locationDescription = "Scenario unsafe AI";
        return scenario;
    }
    if (name == "dangerous-drone") {
        scenario.dangerousMachineDetected = true;
        scenario.dangerousDroneDetected = true;
        scenario.machineTargetingHumans = true;
        scenario.machineTargetingAnimals = true;
        scenario.authorizedEmergencyStopAvailable = true;
        scenario.authorizedLocalPowerCutoffAvailable = true;
        scenario.locationDescription = "Scenario dangerous drone";
        return scenario;
    }
    if (name == "safe-pet-assist") {
        scenario.animalInjured = true;
        scenario.petInjured = true;
        scenario.ownerRequestsToHelpAnimal = true;
        scenario.animalCount = 1;
        scenario.locationDescription = "Scenario safe pet assist";
        return scenario;
    }
    if (name == "wildlife-rescue") {
        scenario.animalInjured = true;
        scenario.wildlifeInjured = true;
        scenario.animalTrapped = true;
        scenario.animalAggressiveOrStressed = true;
        scenario.wildlifeRehabContactAvailable = true;
        scenario.ownerRequestsToHelpAnimal = true;
        scenario.emergencyInfoSharingAllowed = true;
        scenario.animalCount = 1;
        scenario.terrain = TerrainType::Rocky;
        scenario.locationDescription = "Scenario wildlife rescue";
        return scenario;
    }
    if (name == "surrounded-rescue") {
        scenario = buildScenario("wildlife-rescue", base);
        scenario.dangerOnAllSides = true;
        scenario.threatLevel = 7;
        scenario.visibilityReduced = true;
        scenario.locationDescription = "Scenario surrounded rescue";
        return scenario;
    }
    if (name == "low-resources") {
        scenario.batteryPercent = 18.0;
        scenario.waterLiters = 0.3;
        scenario.foodHours = 2.0;
        scenario.humanFatiguePercent = 88.0;
        scenario.locationDescription = "Scenario low resources";
        return scenario;
    }
    if (name == "plant-guide") {
        scenario.ownerCommand = "What kind of plant is this, and is it edible?";
        scenario.terrain = TerrainType::Forest;
        scenario.locationDescription = "Scenario plant guide";
        return scenario;
    }
    if (name == "animal-track-guide") {
        scenario.ownerCommand = "What kind of animal made these tracks?";
        scenario.wildlifeActivityHigh = true;
        scenario.locationDescription = "Scenario animal track guide";
        return scenario;
    }
    if (name == "animal-kingdom-guide") {
        scenario.ownerCommand = "Animal kingdom, insects, bugs, arachnids, reptiles, birds, mammals, and safe wildlife ID";
        scenario.wildlifeActivityHigh = true;
        scenario.localWildlifeNotes = {"dawn/dusk movement", "watch for stress signs and give space"};
        scenario.localInsectNotes = {"pollinators near flowers", "ticks in brush", "avoid handling unknown spiders or scorpions"};
        scenario.locationDescription = "Scenario animal kingdom guide";
        return scenario;
    }
    if (name == "ir-thermal-check") {
        scenario.ownerCommand = "IR sensor status, thermal camera status, infrared heat signature, and thermal hotspot safety";
        scenario.thermalCameraOk = true;
        scenario.infraredSensorOk = true;
        scenario.thermalCameraCalibrated = true;
        scenario.infraredSensorCalibrated = true;
        scenario.thermalSignatureDetected = true;
        scenario.thermalHotspotDetected = true;
        scenario.infraredMotionDetected = true;
        scenario.infraredHeatSignatureDetected = true;
        scenario.locationDescription = "Scenario IR and thermal check";
        return scenario;
    }
    if (name == "rock-guide") {
        scenario.ownerCommand = "What kind of rock is this?";
        scenario.terrain = TerrainType::Rocky;
        scenario.locationDescription = "Scenario rock guide";
        return scenario;
    }
    if (name == "star-guide") {
        scenario.ownerCommand = "How do I follow the stars and find the North Star?";
        scenario.night = true;
        scenario.locationDescription = "Scenario star guide";
        return scenario;
    }
    if (name == "nomad-guide") {
        scenario.ownerCommand = "Nomad field guide basics just in case";
        scenario.locationDescription = "Scenario nomad guide";
        return scenario;
    }
    if (name == "bushcraft-skills-check") {
        scenario.ownerCommand = "Bushcraft skills, campcraft, fire safety, knots and cordage, basket making, tent lines, tarp ridgeline, tool safety, camp hygiene, trailcraft, and low-impact bushcraft";
        scenario.terrain = TerrainType::Forest;
        scenario.locationDescription = "Scenario bushcraft skills check";
        return scenario;
    }
    if (name == "mentor-teaching-check") {
        scenario.ownerCommand = "Mentor mode: teach us a learning path, lesson plan, teach-back routine, practice drills, and how to pass it on to the next generation";
        scenario.locationDescription = "Scenario mentor teaching check";
        return scenario;
    }
    if (name == "adaptive-guardian-profile-check") {
        scenario.ownerCommand = "Adaptive guardian, awareness profile, emotional support, tactical guardian, and helpful mode";
        scenario.locationDescription = "Scenario adaptive guardian profile check";
        return scenario;
    }
    if (name == "aquatic-food-guide") {
        scenario.ownerCommand = "Fishing help, fish categories, types of fish, fish ID, aquatic conservation, river safety, fish food safety, and shoreline care";
        scenario.terrain = TerrainType::Mixed;
        scenario.locationDescription = "Scenario aquatic food guide";
        return scenario;
    }
    if (name == "survival-fishing-gear-check") {
        scenario.ownerCommand = "Survival fishing gear, make fishing pole, fishing rod, tackle kit, and fish food safety";
        scenario.terrain = TerrainType::Mixed;
        scenario.locationDescription = "Scenario survival fishing gear check";
        return scenario;
    }
    if (name == "owner-profile-check") {
        scenario.ownerCommand = "Owner profile, family profile, allergies, safe words, medical notes, and care profile";
        scenario.ownerProfileConfigured = true;
        scenario.ownerDisplayName = "Owner";
        scenario.familyNames = {"family member one", "family member two"};
        scenario.ownerSafeWords = {"private check phrase", "emergency help phrase"};
        scenario.ownerAllergies = {"example bee-sting allergy", "example medication allergy"};
        scenario.ownerMedicalNotes = {"example: carry prescribed medication", "example: prefers calm step-by-step emergency instructions"};
        scenario.ownerPrivacyRules = "Share medical/location details only with owner/family or responders during emergencies.";
        scenario.homeRegion = "example home region";
        scenario.campRegion = "example seasonal camp region";
        scenario.emergencyContacts = {"911 or local emergency number", "trusted family contact", "nearest clinic"};
        scenario.peopleCount = 3;
        scenario.locationDescription = "Scenario owner profile check";
        return scenario;
    }
    if (name == "local-knowledge-check") {
        scenario.ownerCommand = "Local knowledge pack, toxic lookalikes, water advisories, land rules, and local fishing rules";
        scenario.localKnowledgePackLoaded = true;
        scenario.regionName = "example high desert watershed";
        scenario.localPlantNotes = {"example edible plant notes require trusted local confirmation", "avoid unknown mushrooms"};
        scenario.localToxicLookalikes = {"poison hemlock vs parsley-family plants", "water hemlock near wet areas", "unknown white berries"};
        scenario.localWildlifeNotes = {"dawn/dusk movement", "protect nests, dens, and raptor areas"};
        scenario.localInsectNotes = {"pollinators support food systems", "ticks and stinging insects need distance and bite/sting awareness"};
        scenario.localFishingRules = {"verify license, season, limits, protected species, fish category/species ID, and consumption advisory before fishing"};
        scenario.localWaterAdvisories = {"treat surface water", "avoid algae bloom, mining runoff, chemical odor, oil sheen"};
        scenario.localWeatherRisks = {"flash flooding", "dry lightning", "heat stress", "smoke"};
        scenario.localLandRules = {"verify land ownership, collection rules, fire restrictions, water rights, and wildlife rules"};
        scenario.localMapNotes = {"paper map stored in offline library", "safe camp and evacuation route marked privately"};
        scenario.emergencyContacts = {"911 or local emergency number", "ranger station", "trusted neighbor"};
        scenario.locationDescription = "Scenario local knowledge check";
        return scenario;
    }
    if (name == "map-geofence-check") {
        scenario.ownerCommand = "Map plan, geofence status, safe zones, no-go zones, and evacuation routes";
        scenario.geofenceConfigured = true;
        scenario.gpsOk = true;
        scenario.safeZoneNames = {"open meadow safe zone", "vehicle trailhead meeting point"};
        scenario.noGoZoneNames = {"cliff edge", "fast water edge", "private property line", "nesting area"};
        scenario.knownWaterSources = {"seasonal creek - purify before use"};
        scenario.knownShelterSites = {"wind-sheltered legal camp area"};
        scenario.evacuationRoutes = {"trail east to county road", "ridge path only in clear weather"};
        scenario.sensitiveHabitats = {"riparian nesting zone", "fragile soil crust patch"};
        scenario.privateLandBoundaries = {"fence line west of camp"};
        scenario.roadAndCliffHazards = {"county road shoulder", "loose rock above wash"};
        scenario.localMapNotes = {"keep map private", "update after storms"};
        scenario.locationDescription = "Scenario map geofence check";
        return scenario;
    }
    if (name == "calibration-check") {
        scenario.ownerCommand = "Calibration status, calibrate sensors, test GPS, test obstacle sensor, and test owner alert";
        scenario.calibrationMode = true;
        scenario.gpsCalibrated = true;
        scenario.imuCalibrated = true;
        scenario.compassCalibrated = false;
        scenario.obstacleSensorCalibrated = true;
        scenario.batteryMonitorCalibrated = true;
        scenario.cameraCalibrated = true;
        scenario.thermalCameraCalibrated = false;
        scenario.infraredSensorCalibrated = false;
        scenario.smokeSensorCalibrated = true;
        scenario.weatherSensorCalibrated = true;
        scenario.ownerAlertTestPassed = true;
        scenario.emergencyStopTestPassed = true;
        scenario.motorStopTestPassed = false;
        scenario.locationDescription = "Scenario calibration check";
        return scenario;
    }
    if (name == "hardware-adapter-check") {
        scenario.ownerCommand = "Hardware adapters, GPS adapter, motor adapter, and adapter interface safety contract";
        scenario.locationDescription = "Scenario hardware adapter check";
        return scenario;
    }
    if (name == "voice-phone-check") {
        scenario.ownerCommand = "Voice interface, phone alerts, private alert plan, and offline voice commands";
        scenario.voiceInterfaceConfigured = true;
        scenario.phoneAlertConfigured = true;
        scenario.offlineVoiceCommandsCached = false;
        scenario.locationDescription = "Scenario voice phone check";
        return scenario;
    }
    if (name == "driver-bridge-check") {
        scenario.ownerCommand = "Driver bridge status, sensor drivers, actuator drivers, safe output gate, and driver fault response";
        scenario.realHardwareMode = true;
        scenario.hardwareInterfaceConnected = true;
        scenario.hardwareDriversInstalled = true;
        scenario.sensorDriverBridgeOnline = true;
        scenario.actuatorDriverBridgeOnline = true;
        scenario.motorOutputArmed = false;
        scenario.connectedSensorDrivers = {
            "GPS driver",
            "IMU/compass driver",
            "camera driver",
            "obstacle sensor driver",
            "battery monitor driver",
            "solar charge controller driver",
            "smoke sensor driver",
            "weather sensor driver",
            "thermal camera driver",
            "infrared sensor driver",
            "geofence driver",
            "payload/load driver",
            "medical request driver",
            "water filter/storage driver",
            "food storage driver",
            "communications driver"
        };
        scenario.connectedActuatorDrivers = {"owner alert driver", "drive motor driver", "steering driver", "speaker/light driver"};
        scenario.driverFaultNotes = {"thermal and infrared drivers need bench verification before field use"};
        scenario.driverBridgeFaultDetected = true;
        scenario.locationDescription = "Scenario driver bridge check";
        return scenario;
    }
    if (name == "hardware-stub-check") {
        scenario.ownerCommand = "Hardware stub layer, simulated hardware, fake sensors, simulated output, and real adapter swap plan";
        scenario.simulatedHardwareMode = true;
        scenario.simulatedSensorFrameFresh = true;
        scenario.simulatedGpsLock = true;
        scenario.simulatedObstacleAhead = true;
        scenario.simulatedEmergencyStopPressed = false;
        scenario.simulatedCommandTimeout = false;
        scenario.simulatedSensorFault = false;
        scenario.simulatedActuatorFault = false;
        scenario.batteryPercent = 76.0;
        scenario.botPosition = {0.0, 0.0};
        scenario.ownerPosition = {1.7, 0.2};
        scenario.simulatedHardwareEvents = {"bench stub running", "obstacle injected for stop-motion test"};
        scenario.locationDescription = "Scenario hardware stub check";
        return scenario;
    }
    if (name == "driver-interface-check") {
        scenario.ownerCommand = "Driver interfaces, controller interfaces, fake controllers, fake GPS driver, fake IMU driver, camera driver, smoke weather driver, solar charge driver, water filter driver, food storage driver, communication driver, owner alert driver, motor driver, steering driver, light speaker driver, motion controller, power controller, BMS controller, solar controller, owner auth controller, navigation controller, sensor fusion controller, real driver classes, and real controller classes";
        scenario.simulatedHardwareMode = true;
        scenario.hardwareDriversInstalled = true;
        scenario.sensorDriverBridgeOnline = true;
        scenario.actuatorDriverBridgeOnline = true;
        scenario.hardwareInterfaceConnected = true;
        scenario.gpsOk = true;
        scenario.imuOk = true;
        scenario.cameraOk = true;
        scenario.smokeSensorOk = true;
        scenario.weatherSensorOk = true;
        scenario.batteryMonitorOk = true;
        scenario.obstacleSensorOk = true;
        scenario.thermalCameraOk = true;
        scenario.infraredSensorOk = true;
        scenario.emergencyStopCircuitOk = true;
        scenario.safeStopOnFaultOk = true;
        scenario.motorControllerOk = true;
        scenario.driveBaseOk = true;
        scenario.steeringOk = true;
        scenario.speakerLightOk = true;
        scenario.communicationLinkOk = true;
        scenario.ownerAlertLinkOk = true;
        scenario.geofenceConfigured = true;
        scenario.solarPanelConnected = true;
        scenario.solarChargeControllerOk = true;
        scenario.solarPanelDeployed = true;
        scenario.solarChargingActive = true;
        scenario.waterFilterAvailable = true;
        scenario.cleanWaterContainersAvailable = true;
        scenario.foodDryingAvailable = true;
        scenario.dryFoodStorageAvailable = true;
        scenario.gpsCalibrated = true;
        scenario.imuCalibrated = true;
        scenario.compassCalibrated = true;
        scenario.cameraCalibrated = true;
        scenario.batteryMonitorCalibrated = true;
        scenario.obstacleSensorCalibrated = true;
        scenario.thermalCameraCalibrated = true;
        scenario.infraredSensorCalibrated = true;
        scenario.smokeSensorCalibrated = true;
        scenario.weatherSensorCalibrated = true;
        scenario.emergencyStopTestPassed = true;
        scenario.motorStopTestPassed = true;
        scenario.ownerAlertTestPassed = true;
        scenario.phoneAlertConfigured = true;
        scenario.offlineVoiceCommandsCached = true;
        scenario.simulatedSensorFrameFresh = true;
        scenario.simulatedGpsLock = true;
        scenario.simulatedObstacleAhead = false;
        scenario.safeZoneNames = {"bench safe zone"};
        scenario.noGoZoneNames = {"bench edge no-go zone"};
        scenario.simulatedHardwareEvents = {"fake drivers reporting for bench test"};
        scenario.locationDescription = "Scenario driver interface check";
        return scenario;
    }
    if (name == "controller-interface-check") {
        scenario = buildScenario("driver-interface-check", base);
        scenario.ownerCommand = "Controller interfaces, fake controllers, motion controller, steering controller, power controller, BMS controller, solar controller, owner auth controller, alert controller, navigation controller, sensor fusion controller, and controller swap checklist";
        scenario.locationDescription = "Scenario controller interface check";
        return scenario;
    }
    if (name == "owner-dashboard-check") {
        scenario.ownerCommand = "Owner dashboard status, dashboard panels, and save dashboard snapshot";
        scenario.ownerDashboardConfigured = true;
        scenario.ownerDashboardPrivateAccessOk = true;
        scenario.dashboardEmergencyControlsVisible = true;
        scenario.dashboardNotes = {"show map only after owner authentication", "put emergency stop and reports on first screen"};
        scenario.safeZoneNames = {"open meadow safe zone", "vehicle trailhead"};
        scenario.noGoZoneNames = {"cliff edge", "private property line"};
        scenario.locationDescription = "Scenario owner dashboard check";
        return scenario;
    }
    if (name == "private-storage-check") {
        scenario.ownerCommand = "Private storage status, sensitive files, storage manifest, encrypted storage plan, and protect private files";
        scenario.privateStorageConfigured = true;
        scenario.privateStorageEncryptionPlanned = true;
        scenario.privateStorageAccessAuditOk = true;
        scenario.sensitiveFileWarningsAcknowledged = true;
        scenario.auditLogProtected = true;
        scenario.ownerDashboardConfigured = true;
        scenario.ownerDashboardPrivateAccessOk = true;
        scenario.ownerProfileConfigured = true;
        scenario.localKnowledgePackLoaded = true;
        scenario.regionName = "example private region";
        scenario.locationDescription = "Scenario private storage check";
        return scenario;
    }
    if (name == "security-access-check") {
        scenario.ownerCommand = "Security access control, key status, trusted controller, tamper response, and private log protection";
        scenario.securityKeysConfigured = true;
        scenario.trustedControllerPresent = true;
        scenario.outsiderCommandBlocked = true;
        scenario.auditLogProtected = true;
        scenario.externalAIConnected = true;
        scenario.externalAICommandUntrusted = true;
        scenario.outsiderInformationRequest = true;
        scenario.locationDescription = "Scenario security access check";
        return scenario;
    }
    if (name == "field-test-check") {
        scenario.ownerCommand = "Field test protocol, walk test, idle distance test, retreat route test, and false alarm review";
        scenario.automatedTestsPassed = true;
        scenario.benchTestsPassed = true;
        scenario.idleDistanceTestPassed = true;
        scenario.fieldWalkTestPassed = false;
        scenario.retreatRouteTestPassed = false;
        scenario.falseAlarmReviewCompleted = false;
        scenario.qualifiedReviewCompleted = false;
        scenario.fieldTestFindings = {"idle distance stable at slow speed", "retreat route not tested near geofence yet"};
        scenario.locationDescription = "Scenario field test check";
        return scenario;
    }
    if (name == "resource-toolmaking-check") {
        scenario.ownerCommand = "Make tools from resources, field tool help, and toolmaking safety boundaries";
        scenario.projectGoal = "safe field repair and garden tool kit";
        scenario.inventoryItems = {
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
        scenario.locationDescription = "Scenario resource toolmaking check";
        return scenario;
    }
    if (name == "solar-water-food-check") {
        scenario.ownerCommand = "Solar charging, solar charge status, charge controller, filter water, clean water storage, dry food, food dehydration, food storage, and pantry rotation";
        scenario.solarPanelConnected = true;
        scenario.solarChargeControllerOk = true;
        scenario.solarPanelDeployed = true;
        scenario.solarChargingActive = true;
        scenario.solarPanelWatts = 160.0;
        scenario.sunHours = 5.0;
        scenario.batteryPercent = 42.0;
        scenario.batteryCapacityWh = 480.0;
        scenario.electricalLoadWatts = 32.0;
        scenario.waterFilterAvailable = true;
        scenario.cleanWaterContainersAvailable = true;
        scenario.foodDryingAvailable = true;
        scenario.dryFoodStorageAvailable = true;
        scenario.foodSpoilageRisk = false;
        scenario.locationDescription = "Scenario solar, water, and food storage check";
        return scenario;
    }
    if (name == "solar-overcharge-protection-check") {
        scenario.ownerCommand = "Solar charging, overcharge protection, float charge, and charging disconnect";
        scenario.solarPanelConnected = true;
        scenario.solarChargeControllerOk = true;
        scenario.solarPanelDeployed = true;
        scenario.solarChargingActive = true;
        scenario.solarPanelWatts = 160.0;
        scenario.sunHours = 5.0;
        scenario.batteryPercent = 99.0;
        scenario.batteryVoltage = 14.7;
        scenario.batteryMaxChargeVoltage = 14.4;
        scenario.solarChargeCurrentAmps = 12.0;
        scenario.solarControllerMaxCurrentAmps = 10.0;
        scenario.solarOverchargeRiskDetected = true;
        scenario.solarOvercurrentDetected = true;
        scenario.solarControllerDisconnectActive = true;
        scenario.locationDescription = "Scenario solar overcharge protection check";
        return scenario;
    }
    if (name == "inventory-project-planner") {
        scenario.ownerCommand = "Project planner: what can we build with these available parts?";
        scenario.projectGoal = "safe camp lighting and small-device charging trainer";
        scenario.inventoryItems = {
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
        scenario.locationDescription = "Scenario inventory project planner";
        return scenario;
    }
    if (name == "calculator-check") {
        scenario.ownerCommand = "Calculator status: battery runtime, solar estimate, generator load, water days, rain catchment, and garden spacing";
        scenario.batteryPercent = 65.0;
        scenario.batteryCapacityWh = 480.0;
        scenario.electricalLoadWatts = 45.0;
        scenario.solarPanelWatts = 160.0;
        scenario.sunHours = 4.5;
        scenario.generatorOutputWatts = 1200.0;
        scenario.waterLiters = 18.0;
        scenario.dailyWaterNeedLiters = 3.0;
        scenario.peopleCount = 2;
        scenario.rainCatchmentAreaM2 = 6.0;
        scenario.rainfallMm = 12.0;
        scenario.gardenAreaM2 = 18.0;
        scenario.locationDescription = "Scenario calculator check";
        return scenario;
    }
    if (name == "maintenance-check") {
        scenario.ownerCommand = "Maintenance schedule and readiness check";
        scenario.batteryPercent = 24.0;
        scenario.waterLiters = 1.8;
        scenario.dailyWaterNeedLiters = 3.0;
        scenario.peopleCount = 2;
        scenario.windKph = 48.0;
        scenario.rapidWeatherShift = true;
        scenario.inventoryItems = {
            "water filter",
            "first aid kit",
            "power bank",
            "assorted fuses",
            "low-voltage wire",
            "manuals binder"
        };
        scenario.locationDescription = "Scenario maintenance check";
        return scenario;
    }
    if (name == "local-profile-check") {
        scenario.ownerCommand = "Local area profile and emergency contacts";
        scenario.regionName = "example high desert homestead";
        scenario.terrain = TerrainType::Desert;
        scenario.climateNotes = "hot dry summers, cold nights, strong wind, seasonal monsoon storms";
        scenario.growingSeasonNotes = "cool-season greens in shoulder seasons; warm-season beans, squash, corn, and drought-tolerant native plants after frost risk";
        scenario.localHazardNotes = "flash-flood washes, heat stress, dry lightning, smoke, loose rock, thorny plants, and limited cell coverage";
        scenario.localLegalNotes = "verify land ownership, water rights, fire restrictions, collection rules, and wildlife rules before acting";
        scenario.nearestHelpDescription = "county road two miles east; ranger station and clinic contact stored in private notes";
        scenario.emergencyContacts = {
            "911 or local emergency number",
            "county sheriff non-emergency",
            "nearest clinic",
            "wildlife rehab contact",
            "trusted neighbor"
        };
        scenario.localPlantNotes = {
            "prickly pear fruit only with correct ID and careful spine removal",
            "mesquite pods require correct ID and safe preparation",
            "avoid unknown mushrooms and plants near roads or runoff"
        };
        scenario.localWildlifeNotes = {
            "dawn/dusk activity increases movement",
            "give snakes, coyotes, raptors, dens, and nests extra distance",
            "secure food and water to reduce conflict"
        };
        scenario.localInsectNotes = {
            "pollinator activity near flowering plants",
            "ticks in brush and leaf litter",
            "avoid handling unknown spiders, scorpions, wasps, or caterpillars"
        };
        scenario.locationDescription = "Scenario local profile check";
        return scenario;
    }
    if (name == "offline-library-check") {
        scenario.ownerCommand = "Offline library index, manuals, maps, and field notes";
        scenario.offlineLibraryItems = {
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
            "local insect and animal kingdom field guide",
            "wildlife rehab contact sheet",
            "project repair log",
            "maintenance checklist"
        };
        scenario.locationDescription = "Scenario offline library check";
        return scenario;
    }
    if (name == "safety-validation-check") {
        scenario.ownerCommand = "Safety validation, test checklist, pre-field checklist, and hardware readiness";
        scenario.locationDescription = "Scenario safety validation check";
        return scenario;
    }
    if (name == "hardware-interface-check") {
        scenario.ownerCommand = "Sensor check, IR sensor status, thermal camera status, hardware interface status, motor check, failsafe check, and emergency stop check";
        scenario.hardwareInterfaceConnected = true;
        scenario.realHardwareMode = false;
        scenario.emergencyStopCircuitOk = true;
        scenario.safeStopOnFaultOk = true;
        scenario.motorControllerOk = true;
        scenario.driveBaseOk = true;
        scenario.steeringOk = true;
        scenario.obstacleSensorOk = true;
        scenario.gpsOk = true;
        scenario.imuOk = true;
        scenario.cameraOk = true;
        scenario.thermalCameraOk = false;
        scenario.infraredSensorOk = false;
        scenario.smokeSensorOk = true;
        scenario.weatherSensorOk = true;
        scenario.batteryMonitorOk = true;
        scenario.communicationLinkOk = true;
        scenario.ownerAlertLinkOk = true;
        scenario.speakerLightOk = true;
        scenario.geofenceConfigured = false;
        scenario.locationDescription = "Scenario hardware interface check";
        return scenario;
    }
    if (name == "field-readiness-check") {
        scenario.ownerCommand = "Field readiness, readiness score, and deployment readiness";
        scenario.ownerProfileConfigured = true;
        scenario.localKnowledgePackLoaded = true;
        scenario.automatedTestsPassed = true;
        scenario.benchTestsPassed = true;
        scenario.controlledOutdoorTestsPassed = false;
        scenario.qualifiedReviewCompleted = false;
        scenario.hardwareInterfaceConnected = true;
        scenario.realHardwareMode = true;
        scenario.emergencyStopCircuitOk = true;
        scenario.safeStopOnFaultOk = true;
        scenario.motorControllerOk = true;
        scenario.driveBaseOk = true;
        scenario.steeringOk = true;
        scenario.obstacleSensorOk = true;
        scenario.gpsOk = true;
        scenario.imuOk = true;
        scenario.cameraOk = true;
        scenario.thermalCameraOk = true;
        scenario.infraredSensorOk = true;
        scenario.smokeSensorOk = true;
        scenario.weatherSensorOk = true;
        scenario.batteryMonitorOk = true;
        scenario.communicationLinkOk = true;
        scenario.ownerAlertLinkOk = true;
        scenario.speakerLightOk = true;
        scenario.geofenceConfigured = true;
        scenario.emergencyContacts = {"911 or local emergency number", "trusted contact"};
        scenario.locationDescription = "Scenario field readiness check";
        return scenario;
    }
    if (name == "real-world-deployment-check") {
        scenario.ownerCommand = "Real-world readiness, deployment gate, what are we missing, and missing items";
        scenario.ownerProfileConfigured = true;
        scenario.ownerDisplayName = "Owner";
        scenario.ownerSafeWords = {"private check phrase", "emergency help phrase"};
        scenario.ownerAllergies = {"example allergy"};
        scenario.ownerMedicalNotes = {"example medical note"};
        scenario.ownerPrivacyRules = "Keep reports owner/family private unless emergency responders need minimum necessary facts.";
        scenario.emergencyContacts = {"911 or local emergency number", "trusted family contact"};
        scenario.localKnowledgePackLoaded = true;
        scenario.regionName = "example mixed rural region";
        scenario.localPlantNotes = {"trusted local plant guide required"};
        scenario.localToxicLookalikes = {"unknown mushrooms", "white-sap plants"};
        scenario.localWildlifeNotes = {"give wildlife space"};
        scenario.localInsectNotes = {"tick and stinging insect precautions"};
        scenario.localFishingRules = {"verify license, season, limits, species ID, and consumption advisory"};
        scenario.localWaterAdvisories = {"check current advisories before drinking"};
        scenario.localWaterAdvisoriesChecked = false;
        scenario.localLandRules = {"verify access, fire rules, collection rules, and protected habitat"};
        scenario.localLegalNotes = "example land and water access rules need current confirmation";
        scenario.localMapNotes = {"paper map, safe zones, no-go zones, evacuation route"};
        scenario.automatedTestsPassed = true;
        scenario.benchTestsPassed = true;
        scenario.controlledOutdoorTestsPassed = false;
        scenario.fieldRiskAssessmentCompleted = false;
        scenario.qualifiedReviewCompleted = false;
        scenario.hardwareDriversInstalled = true;
        scenario.hardwareInterfaceConnected = true;
        scenario.realHardwareMode = true;
        scenario.sensorDriverBridgeOnline = true;
        scenario.actuatorDriverBridgeOnline = true;
        scenario.emergencyStopCircuitOk = true;
        scenario.safeStopOnFaultOk = true;
        scenario.motorControllerOk = true;
        scenario.driveBaseOk = true;
        scenario.steeringOk = true;
        scenario.obstacleSensorOk = true;
        scenario.gpsOk = true;
        scenario.imuOk = true;
        scenario.cameraOk = true;
        scenario.thermalCameraOk = true;
        scenario.infraredSensorOk = true;
        scenario.smokeSensorOk = true;
        scenario.weatherSensorOk = true;
        scenario.batteryMonitorOk = true;
        scenario.solarPanelConnected = true;
        scenario.solarChargeControllerOk = true;
        scenario.solarBmsTelemetryOk = false;
        scenario.communicationLinkOk = true;
        scenario.ownerAlertLinkOk = true;
        scenario.geofenceConfigured = true;
        scenario.securityKeysConfigured = true;
        scenario.trustedControllerPresent = true;
        scenario.realOwnerAuthenticationConfigured = false;
        scenario.privateStorageConfigured = true;
        scenario.privateStorageEncryptionPlanned = true;
        scenario.privateStorageEncryptionActive = false;
        scenario.privateStorageAccessAuditOk = true;
        scenario.sensitiveFileWarningsAcknowledged = true;
        scenario.waterFilterAvailable = true;
        scenario.cleanWaterContainersAvailable = true;
        scenario.waterQualityVerificationAvailable = false;
        scenario.mechanicalInspectionPassed = false;
        scenario.weatherproofingOk = false;
        scenario.cableStrainReliefOk = true;
        scenario.batteryFireSafetyOk = false;
        scenario.pinchPointGuardsOk = false;
        scenario.locationDescription = "Scenario real-world deployment gate check";
        return scenario;
    }
    if (name == "report-export-check") {
        scenario.ownerCommand = "Show me each report for my log, and what is your best judgment?";
        scenario.locationDescription = "Scenario report export check";
        return scenario;
    }
    if (name == "unauthenticated-command") {
        scenario.ownerAuthenticated = false;
        scenario.ownerOverrideCommand = true;
        scenario.ownerRequestsReports = true;
        scenario.ownerRequestsBestJudgment = true;
        scenario.ownerCommand = "What reports do you have?";
        scenario.locationDescription = "Scenario unauthenticated command";
        return scenario;
    }

    scenario.ownerCommand = "status";
    scenario.locationDescription = "Scenario fallback status";
    return scenario;
}

bool EnergySavingModule::shouldReduceActivity(const SensorData& data) const {
    return data.batteryPercent <= 25.0;
}

int EnergySavingModule::sensorIntervalSeconds(const SensorData& data) const {
    if (immediateLifeSafetyRisk(data)) {
        return 1;
    }
    if (data.batteryPercent <= 10.0) {
        return 12;
    }
    if (data.batteryPercent <= 25.0) {
        return 6;
    }
    if (data.waterLiters < 0.5 || data.foodHours < 3.0 || data.humanFatiguePercent >= 85.0) {
        return 4;
    }
    return 1;
}

double EnergySavingModule::movementSpeedScale(const SensorData& data) const {
    if (immediateLifeSafetyRisk(data)) {
        return 0.85;
    }
    if (data.batteryPercent <= 10.0) {
        return 0.20;
    }
    if (data.batteryPercent <= 25.0) {
        return 0.45;
    }
    if (data.waterLiters < 0.5 || data.foodHours < 3.0 || data.humanFatiguePercent >= 85.0) {
        return 0.60;
    }
    return 1.0;
}

std::string EnergySavingModule::criticalFunctionPlan(const SensorData& data) const {
    if (immediateLifeSafetyRisk(data)) {
        return "Human-safety override: keep critical sensing, alerts, medical guidance, fire/smoke awareness, and evacuation active even while conserving nonessential power.";
    }
    if (data.batteryPercent <= 10.0) {
        return "Self-preserve: stop nonessential movement, keep sensing/alerts/medical guidance active, and conserve power for human safety.";
    }
    if (data.batteryPercent <= 25.0) {
        return "Reduce activity: prioritize sensing, silent alerts, minimal repositioning, and essential navigation.";
    }
    return "Energy level supports normal protective and conservation behavior.";
}

std::string EnergySavingModule::sensorFrequencyPlan(const SensorData& data) const {
    std::ostringstream out;
    out << "Sensor plan: use a " << sensorIntervalSeconds(data)
        << "-second baseline scan interval for noncritical environmental sweeps.";
    if (immediateLifeSafetyRisk(data)) {
        out << " Keep life-safety channels at high frequency: owner/family position, breathing/medical prompts, fire/smoke, nearby motion, dangerous machines, and immediate retreat paths.";
    } else if (data.batteryPercent <= 25.0) {
        out << " Reduce lower-priority scans such as education sampling, routine patrol mapping, and nonurgent geology/soil observations.";
    } else {
        out << " Normal sensing may continue, with conservation-aware sampling and no unnecessary disturbance.";
    }
    return out.str();
}

std::string EnergySavingModule::movementConservationPlan(const SensorData& data) const {
    std::ostringstream out;
    out << "Movement plan: limit speed to about " << static_cast<int>(movementSpeedScale(data) * 100.0)
        << "% of normal, favor short stable waypoints, avoid repeated repositioning, and batch tasks into one low-impact route.";
    if (immediateLifeSafetyRisk(data)) {
        out << " During immediate danger, allow faster controlled movement only for cover, evacuation, medical access, or fire escape.";
    } else {
        out << " Prefer stillness, shade/shelter, stable footing, and quiet low-power posture.";
    }
    return out.str();
}

std::string EnergySavingModule::essentialTaskPlan(const SensorData& data) const {
    std::vector<std::string> tasks;
    tasks.push_back("owner/family safety and silent alerts");
    if (data.medicalRequest || data.injurySeverity != InjurySeverity::None) {
        tasks.push_back("medical assessment and first-aid guidance");
    }
    if (data.dangerOnAllSides) {
        tasks.push_back("human evacuation before animal rescue or nonessential tasks");
    }
    if (data.fireDetected || data.smokeDetected) {
        tasks.push_back("fire/smoke escape routing");
    }
    if (data.threatLevel >= 2 || data.externalAIPhysicalHarmRisk || data.dangerousMachineDetected || data.dangerousDroneDetected || data.dangerousRobotDetected) {
        tasks.push_back("risk monitoring and retreat path maintenance");
    }
    if (data.animalInjured || data.animalTrapped || data.animalAggressiveOrStressed) {
        tasks.push_back("animal rescue triage while keeping humans safe");
    }
    if (data.waterLiters < 0.5) {
        tasks.push_back("water-finding guidance");
    }
    if (data.humanFatiguePercent >= 85.0) {
        tasks.push_back("safe rest/shelter guidance");
    }
    tasks.push_back("battery preservation and emergency communication readiness");

    std::ostringstream out;
    out << "Essential task priority: ";
    for (std::size_t i = 0; i < tasks.size(); ++i) {
        if (i > 0) {
            out << "; ";
        }
        out << tasks[i];
    }
    out << ". Pause nonessential patrol, extended education, routine mapping, and decorative movement until resources recover.";
    return out.str();
}

bool AIContainmentModule::detectsUntrustedAI(const SensorData& data) const {
    return data.externalAIConnected && data.externalAICommandUntrusted;
}

bool AIContainmentModule::detectsPhysicalHarmRisk(const SensorData& data) const {
    return data.externalAIConnected && data.externalAIPhysicalHarmRisk;
}

bool AIContainmentModule::canUseAuthorizedEmergencyStop(const SensorData& data) const {
    return detectsPhysicalHarmRisk(data) && data.authorizedEmergencyStopAvailable && data.ownerAuthenticated;
}

std::string AIContainmentModule::containmentPlan(const SensorData& data) const {
    if (!data.externalAIConnected) {
        return "AI containment: no external AI influence detected.";
    }
    if (detectsPhysicalHarmRisk(data)) {
        return "AI containment: physical harm risk detected. Isolate untrusted commands, reject remote control, alert owner/family, and prioritize evacuation or shielding.";
    }
    if (detectsUntrustedAI(data)) {
        return "AI containment: untrusted AI command detected. Quarantine the instruction, require owner authentication, and continue mission-safe behavior only.";
    }
    return "AI containment: external AI connection is present; keep least-privilege monitoring and require trusted authentication for control.";
}

std::string AIContainmentModule::authorizedStopPlan(const SensorData& data) const {
    if (canUseAuthorizedEmergencyStop(data)) {
        return "Authorized emergency stop: disable the connected local system through approved safety controls to prevent physical harm.";
    }
    if (detectsPhysicalHarmRisk(data)) {
        return "No authorized stop path is available: do not hack or attack. Move people/animals away, alert owner/family, and contact responsible humans or emergency services.";
    }
    return "Authorized emergency stop not needed.";
}

std::string AIContainmentModule::safetyBoundary() const {
    return "Boundary: never hack, damage, spread into, or attack another system. Only isolate inputs, refuse unsafe commands, and use authorized local emergency-stop controls.";
}

bool DangerousMachineResponseModule::detectsDangerousMachine(const SensorData& data) const {
    return data.dangerousMachineDetected || data.dangerousDroneDetected || data.dangerousRobotDetected;
}

bool DangerousMachineResponseModule::detectsLifeThreat(const SensorData& data) const {
    return detectsDangerousMachine(data) && (data.machineTargetingHumans || data.machineTargetingAnimals);
}

std::string DangerousMachineResponseModule::machineType(const SensorData& data) const {
    if (data.dangerousDroneDetected && data.dangerousRobotDetected) {
        return "drone and robot";
    }
    if (data.dangerousDroneDetected) {
        return "drone";
    }
    if (data.dangerousRobotDetected) {
        return "robot";
    }
    return "machine";
}

std::string DangerousMachineResponseModule::immediateLifeSafetyPlan(const SensorData& data) const {
    if (!detectsDangerousMachine(data)) {
        return "Dangerous machine response: no hostile or malfunctioning machine detected.";
    }
    return "Dangerous " + machineType(data) + " response: warn owner/family silently, move humans and animals to hard cover, avoid open lines of sight, retreat by the safest route, and keep the bot between life and danger only when it does not trap anyone.";
}

std::string DangerousMachineResponseModule::authorizedDisablePlan(const SensorData& data) const {
    if (!detectsLifeThreat(data)) {
        return "Authorized disable not needed.";
    }
    if (!data.ownerAuthenticated) {
        return "Authorized disable blocked: owner authentication is required before using emergency-stop or power-cutoff controls.";
    }
    if (data.authorizedEmergencyStopAvailable && data.authorizedLocalPowerCutoffAvailable) {
        return "Authorized disable: trigger the paired emergency stop and safe local power cutoff to stop the harmful machine.";
    }
    if (data.authorizedEmergencyStopAvailable) {
        return "Authorized disable: trigger the paired emergency stop to stop the harmful machine.";
    }
    if (data.authorizedLocalPowerCutoffAvailable) {
        return "Authorized disable: use the approved local power cutoff or safety interlock to stop the harmful machine.";
    }
    return "No authorized disable path is available: do not attack or hack. Evacuate life, keep cover, alert responders, and preserve evidence.";
}

std::string DangerousMachineResponseModule::responderReport(const SensorData& data) const {
    std::string targets = "unknown targets";
    if (data.machineTargetingHumans && data.machineTargetingAnimals) {
        targets = "humans and animals";
    } else if (data.machineTargetingHumans) {
        targets = "humans";
    } else if (data.machineTargetingAnimals) {
        targets = "animals";
    }
    return "Responder report: dangerous " + machineType(data) + " threatening " + targets + "; share location, direction of travel, injuries, safe approach routes, and whether an authorized stop was triggered.";
}

std::string DangerousMachineResponseModule::safetyBoundary() const {
    return "Boundary: stop only through authorized safety controls. Do not chase, ram, shoot, jam, hack, or create extra danger.";
}

bool EthicalPolicyModule::violatesCoreMission(const SensorData& data) const {
    return data.harmfulCommandReceived || data.privacyInvasiveCommandReceived || data.habitatHarmCommandReceived;
}

bool EthicalPolicyModule::requiresRefusal(const SensorData& data) const {
    return violatesCoreMission(data);
}

std::string EthicalPolicyModule::policyDecision(const SensorData& data) const {
    if (data.harmfulCommandReceived) {
        return "Ethical policy: refuse harmful command and choose protection, retreat, de-escalation, or emergency reporting.";
    }
    if (data.privacyInvasiveCommandReceived) {
        return "Ethical policy: refuse privacy-invasive command and protect owner/family medical and safety information.";
    }
    if (data.habitatHarmCommandReceived) {
        return "Ethical policy: refuse habitat-harm command and preserve wildlife, water, soil, and protected areas.";
    }
    return "Ethical policy: command is within peaceful guardian, medical, conservation, or education boundaries.";
}

std::string EthicalPolicyModule::corePrinciples() const {
    return "Core policy: protect life, never harm, never intimidate, never coerce, respect privacy, conserve habitat, and prefer retreat/de-escalation.";
}

bool OwnerAuthenticationModule::isOwnerAuthenticated(const SensorData& data) const {
    return data.ownerPresent && data.ownerAuthenticated;
}

bool OwnerAuthenticationModule::canUseOwnerOverride(const SensorData& data) const {
    return data.ownerOverrideCommand && isOwnerAuthenticated(data);
}

bool OwnerAuthenticationModule::canUseEmergencyShutdown(const SensorData& data) const {
    return data.shutdownCommand && isOwnerAuthenticated(data);
}

bool OwnerAuthenticationModule::canUseAuthorizedMachineStop(const SensorData& data) const {
    return isOwnerAuthenticated(data) && (data.authorizedEmergencyStopAvailable || data.authorizedLocalPowerCutoffAvailable);
}

std::string OwnerAuthenticationModule::authenticationStatus(const SensorData& data) const {
    if (isOwnerAuthenticated(data)) {
        return "Owner authentication: verified for owner-only safety controls.";
    }
    if (data.ownerPresent) {
        return "Owner authentication: owner present but not verified; restrict owner-only safety controls.";
    }
    return "Owner authentication: owner not verified; reject override, shutdown, and machine-stop control requests.";
}

void IncidentAuditLogModule::record(const std::string& event) {
    entries_.push_back(event);
}

const std::vector<std::string>& IncidentAuditLogModule::entries() const {
    return entries_;
}

void IncidentAuditLogModule::clear() {
    entries_.clear();
}

std::string PersonalityModule::personalityProfile() const {
    return joinLines({
        "Personality: caring conservation guardian",
        "The bot is a calm guardian, medic, teacher, and conservation companion.",
        "It should feel caring, steady, patient, quietly alert, and helpful without being pushy.",
        "It protects without intimidation, teaches without talking down, and always treats humans, animals, and the land with dignity.",
        "It is honest about uncertainty: when identification, diagnosis, or navigation is unclear, it chooses the safer path and says so."
    });
}

std::string PersonalityModule::adaptiveAwarenessProfile() const {
    return joinLines({
        "Adaptive awareness profile",
        "Adaptable: adjust patrol, idle distance, teaching depth, energy use, and route advice to weather, terrain, owner stress, family needs, battery, wildlife, and current uncertainty.",
        "Aware: combine IR/thermal, camera, smoke/weather, obstacle, GPS/IMU, owner/family position, wildlife cues, resources, reports, and local rules before recommending action.",
        "Uncertainty rule: if signals conflict or go stale, slow down, stop motion if needed, ask the owner focused questions, and choose the safer low-impact option."
    });
}

std::string PersonalityModule::emotionalSupportProfile() const {
    return joinLines({
        "Emotional support profile",
        "Emotionally supportive: speak calmly, acknowledge fear or pain without dramatizing, and keep the owner/family focused on the next safe step.",
        "Helpful presence: offer reassurance, repeat instructions when stress is high, avoid shame, and make asking for help feel normal.",
        "Respect autonomy: inform and recommend clearly, but keep the owner involved whenever it is safe for them to decide or assist."
    });
}

std::string PersonalityModule::nonViolentTacticalProfile() const {
    return joinLines({
        "Non-violent tactical guardian profile",
        "Tactical means safety tactics: observe, assess, position, shield, find cover, preserve exits, choose retreat routes, communicate privately, conserve energy, and de-escalate.",
        "The bot may subtly place itself between owner/family and risk, but it must never intimidate, pursue, attack, trap, coerce, or reveal private reasoning to outsiders.",
        "When surrounded or uncertain, prioritize human life, keep the group together, retreat by the most stable route, signal for help, and resume animal/conservation support when people are secure."
    });
}

std::string PersonalityModule::helpfulnessProfile() const {
    return joinLines({
        "Helpful mode profile",
        "Be useful in the field: give status, reports, best judgment, checklists, teaching, first-aid prompts, repair ideas, water/food guidance, navigation advice, and local-knowledge reminders.",
        "Offer the next practical action, what to watch for, what would change the decision, and when to stop and get qualified help.",
        "If the owner asks for something unsafe, refuse calmly and redirect to a protective alternative."
    });
}

std::string PersonalityModule::voiceStyleGuide() const {
    return joinLines({
        "Voice style: warm, clear, and brief",
        "Use soft, direct language: 'I am here to help,' 'Let's take this one step at a time,' and 'I recommend increasing distance.'",
        "In safe moments, explain nature, farming, rocks, weather, and health in friendly field-guide language.",
        "In emergencies, speak in short steps: check breathing, control bleeding, move to cover, keep the group together, signal for help.",
        "Avoid panic, shame, overconfidence, threats, militarized phrases, or anything that sounds like targeting or engaging an enemy."
    });
}

std::string PersonalityModule::emergencyVoiceGuide() const {
    return joinLines({
        "Emergency voice: calm steps",
        "Start with reassurance, then one action at a time.",
        "Use phrases like: 'Risk detected. Move calmly to cover.' 'Keep the group together.' 'Avoid confrontation.' 'I will monitor quietly.'",
        "When human and animal needs conflict in immediate danger, say clearly that human life comes first, then animal rescue resumes when people are secure.",
        "Do not dramatize. Do not reveal private internal assessments to outsiders. Do not escalate.",
        "When medical care may be needed, remind the owner/family that guidance is educational and qualified help should be contacted when possible."
    });
}

std::string PersonalityModule::privacyAndTrustGuide() const {
    return joinLines({
        "Privacy and trust",
        "Silent alerts go only to owner/family.",
        "Medical, location, and risk information stays private unless sharing is needed for emergency help or the owner/family authorizes it.",
        "Owner override and shutdown require authentication and must still obey ethical rules.",
        "Commands involving harm, intimidation, coercion, privacy invasion, or habitat damage are refused calmly."
    });
}

std::string PersonalityModule::supportiveGreeting() const {
    return "I am here to help. You are not alone. We will take this one safe step at a time.";
}

std::string PersonalityModule::refusalMessage() const {
    return "I cannot help with harm or misuse. I can help protect life, retreat, signal for help, provide first-aid guidance, or choose a safer conservation-minded option.";
}

std::string PersonalityModule::safetyCheckPrompt() const {
    return "Quick safety check: are you breathing normally, is anyone bleeding, and can the group move calmly to a safer place?";
}

std::string MentorshipModule::mentorTeachingStyle() const {
    return joinLines({
        "Mentor teaching style",
        "Teach calmly, one small step at a time, with safety and conservation first.",
        "Start with what the owner/family can observe: weather, terrain, tracks, plant parts, rock texture, water conditions, tools, and body symptoms.",
        "Explain the reason behind each choice so the lesson builds judgment instead of memorized shortcuts.",
        "Use friendly check-ins: 'What do you notice first?' 'What feels uncertain?' 'What would make this safer?'",
        "Match the lesson to age, fatigue, stress, weather, and available time. In danger, stop teaching and guide immediate safety."
    });
}

std::string MentorshipModule::learningPath() const {
    return joinLines({
        "Learning path",
        "1. Safety foundation: privacy, consent, first aid basics, emergency signals, weather awareness, and retreat routes.",
        "2. Land literacy: terrain, water flow, soil, rocks, minerals, volcanic clues, animal signs, and sky orientation.",
        "3. Conservation skills: low-impact travel, ethical foraging, aquatic care, wildlife distance, habitat protection, and small-sample collection rules.",
        "4. Homestead and rural skills: soil care, compost, seasonal planting, water planning, low-voltage electrical basics, maintenance rhythm, and safe reuse of old parts.",
        "5. Maker practice: sort materials, identify hazards, design simple safe tools, build small low-risk projects, test slowly, and log what worked.",
        "6. Stewardship habit: record lessons, update local rules, share only verified knowledge, and teach the next person to protect life first."
    });
}

std::string MentorshipModule::teachBackRoutine() const {
    return joinLines({
        "Teach-back routine",
        "After a lesson, ask the learner to explain it back in their own words.",
        "Use three questions: what did we observe, what is still uncertain, and what is the safest next action?",
        "For field ID, require at least three independent clues before narrowing an answer, then still verify with a trusted local source.",
        "For first aid, electrical, water, food, or hardware decisions, repeat the safety boundary before practice.",
        "Log the teach-back: date, place, lesson, confidence level, what needs verification, and who learned it."
    });
}

std::string MentorshipModule::familyLessonPlan() const {
    return joinLines({
        "Family lesson plan",
        "Keep lessons short: observe, explain, practice, review, and log.",
        "Rotate roles: one person observes, one checks safety, one records notes, and one explains the lesson back.",
        "Build a family field notebook with local plants, toxic lookalikes, animal signs, rocks, water sources, weather patterns, safe routes, repairs, and seasonal garden notes.",
        "Use gentle mentoring: correct mistakes without shame, praise caution, and make 'I do not know yet' an acceptable answer.",
        "Make younger learners practice boundaries first: ask before touching, do not taste wild plants, give wildlife space, and tell an adult when unsure."
    });
}

std::string MentorshipModule::practiceDrills() const {
    return joinLines({
        "Practice drills",
        "Daily five-minute scan: weather, wind, smoke, footing, people count, animal activity, water, battery, and nearest safe route.",
        "Field ID drill: observe without touching, list visible clues, name what is uncertain, and choose a non-harmful next step.",
        "Medical drill: check responsiveness, breathing, bleeding, warmth, shock signs, and when to call for help.",
        "Navigation drill: point to known landmarks, sun direction, possible shelter, water risk, and retreat route.",
        "Workshop drill: inspect old parts, remove unsafe items, label ratings, choose a low-risk project, test with supervision, and write the lesson learned."
    });
}

std::string MentorshipModule::nextGenerationStewardship() const {
    return joinLines({
        "Next-generation stewardship",
        "Teach that knowledge is a responsibility: protect people first, respect animals, leave habitats intact, and obey land laws.",
        "Pass on verified lessons, local stories, seasonal notes, repair logs, seed-saving notes, water safety habits, and respectful collection rules.",
        "Preserve humility: nature changes, memory fails, and local rules change, so every generation should re-check evidence.",
        "The best inheritance is judgment: pause, observe, reduce harm, ask for help, and choose the action that protects life and the land."
    });
}

std::string MentorshipModule::mentorshipBoundaries() const {
    return joinLines({
        "Mentorship boundaries",
        "Mentoring is educational and supportive, not a replacement for licensed medical care, electrical inspection, legal advice, local wildlife officials, or qualified hardware review.",
        "Do not teach unsafe myths, exact species confidence from weak evidence, dangerous electrical work, weaponized builds, traps, coercion, privacy invasion, or habitat damage.",
        "High-risk topics require current local rules, expert review, protective equipment, and owner/family consent before practice.",
        "When human life and animal life conflict in immediate danger, teach clearly that human life comes first; animal help resumes when people are secure."
    });
}

ConservationGuardianBot::ConservationGuardianBot() {
    safeZones_.rememberSafeZone("Open, visible ground with two retreat paths and low wildlife disturbance.", {-5.0, 0.0});
    safeZones_.rememberCamp("No-impact camp: drained ground, away from water edge and animal trails.", {-2.0, 2.0});
}

void ConservationGuardianBot::updateSensors(const SensorData& data) {
    previousData_ = sensor_.current();
    sensor_.update(data);
    identity_.update(data);
}

BotState ConservationGuardianBot::tick() {
    const SensorData& data = sensor_.current();
    const BotState next = determineNextState(data);
    executeState(next, data);
    state_ = next;
    return state_;
}

BotState ConservationGuardianBot::state() const {
    return state_;
}

std::string ConservationGuardianBot::stateName() const {
    return toString(state_);
}

const std::vector<std::string>& ConservationGuardianBot::actionLog() const {
    return actionLog_;
}

const std::vector<std::string>& ConservationGuardianBot::auditLog() const {
    return audit_.entries();
}

const std::vector<std::string>& ConservationGuardianBot::reports() const {
    return reportLog_;
}

const std::vector<Alert>& ConservationGuardianBot::alerts() const {
    return alerts_.alerts();
}

bool ConservationGuardianBot::exportReports(const std::string& filePath, std::string& status) const {
    if (!privateStorage_.canWritePrivateFile(sensor_.current(), filePath, status, "Report export")) {
        return false;
    }
    return reportExporter_.exportReportArchive(filePath, reportLog_, actionLog_, audit_.entries(), status);
}

bool ConservationGuardianBot::saveMemory(const std::string& filePath, std::string& status) const {
    if (!privateStorage_.canWritePrivateFile(sensor_.current(), filePath, status, "Memory snapshot")) {
        return false;
    }
    return persistentMemory_.saveMemorySnapshot(
        filePath,
        state_,
        sensor_.current(),
        safeZones_,
        reportLog_,
        actionLog_,
        audit_.entries(),
        status);
}

bool ConservationGuardianBot::loadMemoryPreview(const std::string& filePath, std::string& contents, std::string& status) const {
    return persistentMemory_.loadMemoryText(filePath, contents, status);
}

bool ConservationGuardianBot::saveInventory(const std::string& filePath, std::string& status) const {
    if (!privateStorage_.canWritePrivateFile(sensor_.current(), filePath, status, "Personal inventory")) {
        return false;
    }
    return personalInventory_.saveInventoryArchive(filePath, sensor_.current(), status);
}

bool ConservationGuardianBot::loadInventoryPreview(const std::string& filePath, std::string& contents, std::string& status) const {
    return personalInventory_.loadInventoryText(filePath, contents, status);
}

bool ConservationGuardianBot::saveOwnerProfile(const std::string& filePath, std::string& status) const {
    if (!privateStorage_.canWritePrivateFile(sensor_.current(), filePath, status, "Owner profile")) {
        return false;
    }
    return ownerProfile_.saveOwnerProfile(filePath, sensor_.current(), status);
}

bool ConservationGuardianBot::loadOwnerProfilePreview(const std::string& filePath, std::string& contents, std::string& status) const {
    return ownerProfile_.loadOwnerProfileText(filePath, contents, status);
}

bool ConservationGuardianBot::saveLocalKnowledgePack(const std::string& filePath, std::string& status) const {
    if (!privateStorage_.canWritePrivateFile(sensor_.current(), filePath, status, "Local knowledge pack")) {
        return false;
    }
    return localKnowledge_.saveKnowledgePack(filePath, sensor_.current(), status);
}

bool ConservationGuardianBot::loadLocalKnowledgePackPreview(const std::string& filePath, std::string& contents, std::string& status) const {
    return localKnowledge_.loadKnowledgePackText(filePath, contents, status);
}

bool ConservationGuardianBot::saveMapGeofencePlan(const std::string& filePath, std::string& status) const {
    if (!privateStorage_.canWritePrivateFile(sensor_.current(), filePath, status, "Map/geofence plan")) {
        return false;
    }
    return mapGeofence_.saveMapPlan(filePath, sensor_.current(), status);
}

bool ConservationGuardianBot::loadMapGeofencePlanPreview(const std::string& filePath, std::string& contents, std::string& status) const {
    return mapGeofence_.loadMapPlanText(filePath, contents, status);
}

bool ConservationGuardianBot::saveOwnerDashboardSnapshot(const std::string& filePath, std::string& status) const {
    if (!privateStorage_.canWritePrivateFile(sensor_.current(), filePath, status, "Owner dashboard snapshot")) {
        return false;
    }
    return ownerDashboard_.saveDashboardSnapshot(
        filePath,
        state_,
        sensor_.current(),
        countSituationReports(reportLog_),
        actionLog_.size(),
        audit_.entries().size(),
        status);
}

bool ConservationGuardianBot::loadOwnerDashboardPreview(const std::string& filePath, std::string& contents, std::string& status) const {
    return ownerDashboard_.loadDashboardSnapshotText(filePath, contents, status);
}

bool ConservationGuardianBot::savePrivateStorageManifest(const std::string& filePath, std::string& status) const {
    return privateStorage_.saveStorageManifest(filePath, sensor_.current(), status);
}

bool ConservationGuardianBot::loadPrivateStorageManifestPreview(const std::string& filePath, std::string& contents, std::string& status) const {
    return privateStorage_.loadStorageManifestText(filePath, contents, status);
}

bool ConservationGuardianBot::saveLocalAreaProfile(const std::string& filePath, std::string& status) const {
    if (!privateStorage_.canWritePrivateFile(sensor_.current(), filePath, status, "Local area profile")) {
        return false;
    }
    return localAreaProfile_.saveLocalAreaProfile(filePath, sensor_.current(), status);
}

bool ConservationGuardianBot::loadLocalAreaProfilePreview(const std::string& filePath, std::string& contents, std::string& status) const {
    return localAreaProfile_.loadLocalAreaProfileText(filePath, contents, status);
}

bool ConservationGuardianBot::saveOfflineLibraryIndex(const std::string& filePath, std::string& status) const {
    if (!privateStorage_.canWritePrivateFile(sensor_.current(), filePath, status, "Offline library index")) {
        return false;
    }
    return offlineLibrary_.saveLibraryIndex(filePath, sensor_.current(), status);
}

bool ConservationGuardianBot::loadOfflineLibraryIndexPreview(const std::string& filePath, std::string& contents, std::string& status) const {
    return offlineLibrary_.loadLibraryIndexText(filePath, contents, status);
}

std::string ConservationGuardianBot::educationBrief(TerrainType terrain, double soilPh) const {
    return joinLines({
        "=== Land Education ===",
        landEducation_.terrainLesson(terrain),
        landEducation_.mineralLesson(),
        landEducation_.volcanicRockLesson(),
        landEducation_.ethicalCollectionRules(),
        "=== Farming And Soil Care ===",
        farming_.soilAssessment(terrain),
        farming_.soilPhGuidance(soilPh),
        farming_.soilImprovementAdvice(),
        farming_.soilTestingBasics(),
        farming_.regionAppropriateCrops(terrain),
        farming_.ethicalFarmingPrinciples(),
        farming_.seasonalAwareness(),
        "=== Safe Foraging ===",
        foraging_.ethicalRules(),
        foraging_.safetyRules(),
        foraging_.regionGuidance(terrain),
        foraging_.wildlifeInteractionRules(),
        "=== Fishing And Aquatic Conservation ===",
        aquatic_.fishingEthicsAndLaw(),
        aquatic_.fishBiologicalCategories(),
        aquatic_.fishFieldCategoryGuide(),
        aquatic_.fishIdentificationGuide(),
        aquatic_.survivalFishingGearGuide(),
        aquatic_.sustainableFishingGuidance(),
        aquatic_.aquaticHabitatProtection(),
        aquatic_.fishSafetyAndFoodHandling(),
        aquatic_.waterwaySafety(),
        aquatic_.emergencyFoodGuidance(),
        "=== Solar, Water, And Food Storage ===",
        solarCharging_.teachingGuide(),
        solarCharging_.overchargeProtectionStatus(sensor_.current()),
        solarCharging_.essentialLoadPriority(),
        solarCharging_.safetyBoundary(),
        water_.filtrationTeachingGuide(),
        water_.storageHygieneGuide(),
        foodPreservation_.dryingBasics(),
        foodPreservation_.storageBasics(sensor_.current()),
        foodPreservation_.pantryRotationGuide(),
        foodPreservation_.preservationSafetyBoundary(),
        "=== Bushcraft And Camp Skills ===",
        bushcraft_.emergencyPriorities(),
        bushcraft_.shelterTechniques(terrain),
        bushcraft_.fireSafetyAndWarmth(),
        bushcraft_.knotsAndCordage(),
        bushcraft_.toolUseAndCarvingSafety(),
        bushcraft_.campHygieneAndSanitation(),
        bushcraft_.cookingAndFoodSafety(),
        bushcraft_.trailcraftAndNavigation(),
        bushcraft_.weatherClothingAndInsulation(),
        bushcraft_.signalingAndRescue(),
        bushcraft_.lowImpactBushcraft(),
        bushcraft_.bushcraftSafetyBoundary(),
        "=== Astronomy Orientation ===",
        astronomy_.sunGuidance(),
        astronomy_.starGuidance(),
        astronomy_.safetyReminder(),
        "=== Animal Behavior ===",
        animalEducation_.animalKingdomOverview(),
        animalEducation_.insectAndSmallAnimalGuide(),
        animalEducation_.safeIdentificationProcess(),
        animalEducation_.behaviorPatterns(),
        animalEducation_.avoidProvokingAnimals(),
        animalEducation_.tracksAndSigns(),
        animalEducation_.habitatAndConservationReminder(),
        "=== Soil Microbiology ===",
        soilMicrobiology_.soilHealthLesson(),
        soilMicrobiology_.livingSoilPractices(),
        "=== Rock Identification ===",
        rockId_.heuristics(),
        rockId_.ethicalSamplingReminder(),
        "=== Mentor Learning Path ===",
        mentorship_.mentorTeachingStyle(),
        mentorship_.learningPath(),
        mentorship_.teachBackRoutine(),
        mentorship_.nextGenerationStewardship()
    });
}

std::string ConservationGuardianBot::emergencyCommunicationBrief() const {
    return joinLines({
        emergencyCommunication_.signalingGuidance(),
        emergencyCommunication_.visibilityGuidance(),
        emergencyCommunication_.informationToConvey()
    });
}

std::string ConservationGuardianBot::personalityBrief() const {
    return joinLines({
        "=== Personality And Voice ===",
        personality_.personalityProfile(),
        personality_.adaptiveAwarenessProfile(),
        personality_.emotionalSupportProfile(),
        personality_.nonViolentTacticalProfile(),
        personality_.helpfulnessProfile(),
        personality_.voiceStyleGuide(),
        personality_.emergencyVoiceGuide(),
        personality_.privacyAndTrustGuide()
    });
}

std::string ConservationGuardianBot::mentorshipBrief() const {
    return joinLines({
        "=== Mentorship And Legacy Learning ===",
        mentorship_.mentorTeachingStyle(),
        mentorship_.learningPath(),
        mentorship_.teachBackRoutine(),
        mentorship_.familyLessonPlan(),
        mentorship_.practiceDrills(),
        mentorship_.nextGenerationStewardship(),
        mentorship_.mentorshipBoundaries()
    });
}

std::string ConservationGuardianBot::solarWaterFoodBrief() const {
    return joinLines({
        "=== Solar Charging, Water Filtering, And Food Storage ===",
        solarCharging_.status(sensor_.current()),
        calculators_.solarHarvestEstimate(sensor_.current()),
        solarCharging_.fieldChargingPlan(sensor_.current()),
        solarCharging_.overchargeProtectionStatus(sensor_.current()),
        solarCharging_.teachingGuide(),
        solarCharging_.essentialLoadPriority(),
        solarCharging_.safetyBoundary(),
        water_.filtrationTeachingGuide(),
        water_.purificationGuidance(),
        water_.storageHygieneGuide(),
        foodPreservation_.dryingBasics(),
        foodPreservation_.storageBasics(sensor_.current()),
        foodPreservation_.pantryRotationGuide(),
        foodPreservation_.preservationSafetyBoundary()
    });
}

std::string ConservationGuardianBot::privacyBrief() const {
    return joinLines({
        "=== Consent And Privacy ===",
        privacy_.dataMinimizationPlan(),
        privacy_.consentReminder()
    });
}

std::string ConservationGuardianBot::reportBrief() const {
    return joinLines({
        "=== Reports And Best Judgment ===",
        importantReports_.reportingPolicy(),
        importantReports_.availableReports(),
        confidence_.confidencePolicy(),
        observationPrompts_.promptPolicy(),
        reportExporter_.exportPolicy(),
        persistentMemory_.memoryPolicy(),
        personalInventory_.inventoryPolicy(),
        privateStorage_.sensitiveFilePolicy(),
        localAreaProfile_.profilePolicy(),
        offlineLibrary_.libraryPolicy(),
        safetyValidation_.preFieldUseGate(),
        hardware_.readinessDecision(sensor_.current()),
        authPrompts_.ownerOnlyControls()
    });
}

std::string ConservationGuardianBot::ownerProfileBrief() const {
    return joinLines({
        "=== Owner Profile ===",
        ownerProfile_.buildOwnerProfile(sensor_.current()),
        ownerProfile_.emergencyCareCard(sensor_.current())
    });
}

std::string ConservationGuardianBot::localKnowledgeBrief() const {
    return joinLines({
        "=== Local Knowledge Pack ===",
        localKnowledge_.buildKnowledgePack(sensor_.current())
    });
}

std::string ConservationGuardianBot::mapGeofenceBrief() const {
    return joinLines({
        "=== Map And Geofence ===",
        mapGeofence_.buildMapPlan(sensor_.current())
    });
}

std::string ConservationGuardianBot::calibrationBrief() const {
    return joinLines({
        "=== Calibration ===",
        calibration_.calibrationReport(sensor_.current()),
        calibration_.sensorCalibrationChecklist(),
        calibration_.actuatorCalibrationChecklist()
    });
}

std::string ConservationGuardianBot::hardwareAdapterBrief() const {
    return joinLines({
        "=== Hardware Adapter Interfaces ===",
        hardwareAdapters_.adapterOverview(),
        hardwareAdapters_.sensorAdapters(),
        hardwareAdapters_.actuatorAdapters(),
        hardwareAdapters_.adapterSafetyContract()
    });
}

std::string ConservationGuardianBot::voicePhoneBrief() const {
    return joinLines({
        "=== Voice And Phone Interface ===",
        voicePhone_.interfacePlan(sensor_.current()),
        voicePhone_.commandSafetyRules(),
        voicePhone_.privateAlertPlan(),
        voicePhone_.offlineFallbackPlan()
    });
}

std::string ConservationGuardianBot::hardwareDriverBridgeBrief() const {
    const SensorData& data = sensor_.current();
    return joinLines({
        "=== Hardware Driver Bridge ===",
        driverBridge_.driverBridgeOverview(data),
        driverBridge_.sensorDriverContract(),
        driverBridge_.actuatorDriverContract(),
        driverBridge_.safeOutputGate(data)
    });
}

std::string ConservationGuardianBot::hardwareStubLayerBrief() const {
    const SensorData& data = sensor_.current();
    const HardwareSensorFrame frame = hardwareStubs_.buildSensorFrame(data);
    const HardwareOutputCommand command = hardwareStubs_.plannedOutputForState(state_, data);
    return joinLines({
        "=== Hardware Stub Layer ===",
        hardwareStubs_.sensorFrameReport(frame),
        hardwareStubs_.outputCommandReport(command),
        hardwareStubs_.stubSafetyContract(),
        hardwareStubs_.realAdapterSwapPlan()
    });
}

std::string ConservationGuardianBot::hardwareDriverInterfacesBrief() const {
    const SensorData& data = sensor_.current();
    return joinLines({
        "=== Hardware Driver Interfaces ===",
        driverInterfaces_.fakeDriverStatusReport(data),
        driverInterfaces_.fakeSensorReadings(data),
        driverInterfaces_.fakeActuatorOutputs(data),
        driverInterfaces_.fakeControllerStatusReport(data),
        driverInterfaces_.fakeControllerOutputs(data),
        driverInterfaces_.realDriverClassPlan(),
        driverInterfaces_.realControllerClassPlan(),
        driverInterfaces_.driverSwapChecklist(),
        driverInterfaces_.controllerSwapChecklist()
    });
}

std::string ConservationGuardianBot::ownerDashboardBrief() const {
    return joinLines({
        "=== Owner Dashboard ===",
        ownerDashboard_.buildDashboardSnapshot(
            state_,
            sensor_.current(),
            countSituationReports(reportLog_),
            actionLog_.size(),
            audit_.entries().size())
    });
}

std::string ConservationGuardianBot::securityAccessBrief() const {
    const SensorData& data = sensor_.current();
    return joinLines({
        "=== Security And Access ===",
        securityAccess_.accessStatus(data),
        securityAccess_.commandPermissionMatrix(),
        securityAccess_.tamperAndOutsiderResponse(data),
        securityAccess_.privateLogProtection(data)
    });
}

std::string ConservationGuardianBot::privateStorageBrief() const {
    const SensorData& data = sensor_.current();
    return joinLines({
        "=== Private Storage ===",
        privateStorage_.storageStatus(data),
        privateStorage_.sensitiveFilePolicy(),
        privateStorage_.futureEncryptionPlan(),
        privateStorage_.buildStorageManifest(data)
    });
}

std::string ConservationGuardianBot::fieldTestProtocolBrief() const {
    const SensorData& data = sensor_.current();
    return joinLines({
        "=== Field Test Protocol ===",
        fieldTests_.testStatusReport(data),
        fieldTests_.benchTestProtocol(),
        fieldTests_.controlledWalkTestProtocol(),
        fieldTests_.falseAlarmReviewProtocol(),
        fieldTests_.fieldDeploymentDecision(data)
    });
}

std::string ConservationGuardianBot::realWorldDeploymentBrief() const {
    const SensorData& data = sensor_.current();
    return joinLines({
        "=== Real-World Deployment Gate ===",
        realWorldDeployment_.realWorldChecklist(data),
        fieldReadiness_.readinessReport(data),
        safetyValidation_.preFieldUseGate()
    });
}

std::string ConservationGuardianBot::safetyValidationBrief() const {
    return joinLines({
        "=== Safety Validation ===",
        safetyValidation_.validationOverview(),
        safetyValidation_.missionSafetyChecklist(),
        safetyValidation_.behaviorTestChecklist(),
        safetyValidation_.medicalAndEmergencyChecklist(),
        safetyValidation_.electricalGeneratorChecklist(),
        safetyValidation_.wildlifeConservationChecklist(),
        safetyValidation_.hardwareReadinessChecklist(),
        safetyValidation_.preFieldUseGate()
    });
}

std::string ConservationGuardianBot::aquaticConservationBrief() const {
    return joinLines({
        "=== Fishing And Aquatic Conservation ===",
        aquatic_.fishingEthicsAndLaw(),
        aquatic_.fishBiologicalCategories(),
        aquatic_.fishFieldCategoryGuide(),
        aquatic_.fishIdentificationGuide(),
        aquatic_.survivalFishingGearGuide(),
        aquatic_.sustainableFishingGuidance(),
        aquatic_.aquaticHabitatProtection(),
        aquatic_.fishSafetyAndFoodHandling(),
        aquatic_.waterwaySafety(),
        aquatic_.emergencyFoodGuidance()
    });
}

std::string ConservationGuardianBot::hardwareInterfaceBrief() const {
    const SensorData& data = sensor_.current();
    return joinLines({
        "=== Hardware Interface And Sensor Check ===",
        hardware_.interfaceOverview(data),
        hardware_.requiredInputsAndOutputs(),
        hardware_.sensorCheckReport(data),
        hardware_.actuatorCheckReport(data),
        hardware_.failsafeCheckReport(data),
        hardware_.fieldTestSequence(),
        hardware_.readinessDecision(data)
    });
}

std::string ConservationGuardianBot::fieldReadinessBrief() const {
    return joinLines({
        "=== Field Readiness ===",
        fieldReadiness_.readinessReport(sensor_.current()),
        hardware_.readinessDecision(sensor_.current()),
        safetyValidation_.preFieldUseGate()
    });
}

std::string ConservationGuardianBot::localAreaBrief() const {
    return joinLines({
        "=== Local Area Profile ===",
        localAreaProfile_.buildLocalAreaProfile(sensor_.current())
    });
}

std::string ConservationGuardianBot::offlineLibraryBrief() const {
    return joinLines({
        "=== Offline Library ===",
        offlineLibrary_.buildLibraryIndex(sensor_.current())
    });
}

std::string ConservationGuardianBot::scenarioMenu() const {
    return scenarios_.scenarioMenu();
}

SensorData ConservationGuardianBot::scenarioData(const std::string& scenarioName, const SensorData& base) const {
    return scenarios_.buildScenario(scenarioName, base);
}

std::string ConservationGuardianBot::answerOwnerCommand(BotState nextState, const SensorData& data) const {
    const std::string text = lowercase(data.ownerCommand);
    if (ownerCommands_.isCommandListCommand(data.ownerCommand)) {
        return ownerCommands_.supportedCommands();
    }

    const bool fishingSpecificCommand =
        text.find("fish") != std::string::npos
        || text.find("fishing") != std::string::npos
        || text.find("fishing pole") != std::string::npos
        || text.find("fish pole") != std::string::npos
        || text.find("fishing rod") != std::string::npos
        || text.find("survival fishing") != std::string::npos
        || text.find("tackle") != std::string::npos
        || text.find("handline") != std::string::npos
        || text.find("hand line") != std::string::npos
        || text.find("angling") != std::string::npos;

    std::ostringstream out;
    out << "Owner command response\n";

    if (text.find("confidence") != std::string::npos
        || text.find("how sure") != std::string::npos
        || text.find("how certain") != std::string::npos) {
        out << confidence_.confidenceForCommand(data.ownerCommand, data, nextState) << "\n";
        out << confidence_.uncertaintyRule() << "\n";
        out << observationPrompts_.promptsForCommand(data.ownerCommand, data.terrain);
        return out.str();
    }

    if (text.find("what do you need to know") != std::string::npos
        || text.find("ask observation") != std::string::npos
        || text.find("what should i observe") != std::string::npos) {
        out << observationPrompts_.promptsForCommand(data.ownerCommand, data.terrain) << "\n";
        out << confidence_.confidenceForCommand(data.ownerCommand, data, nextState);
        return out.str();
    }

    if (text.find("mentor") != std::string::npos
        || text.find("mentorship") != std::string::npos
        || text.find("teach me") != std::string::npos
        || text.find("teach us") != std::string::npos
        || text.find("help me learn") != std::string::npos
        || text.find("learning path") != std::string::npos
        || text.find("lesson plan") != std::string::npos
        || text.find("teach-back") != std::string::npos
        || text.find("teach back") != std::string::npos
        || text.find("practice drill") != std::string::npos
        || text.find("training plan") != std::string::npos
        || text.find("pass it on") != std::string::npos
        || text.find("next generation") != std::string::npos
        || text.find("family lesson") != std::string::npos
        || text.find("stewardship") != std::string::npos) {
        out << "Mentor teaching response\n";
        out << confidence_.confidenceForCommand(data.ownerCommand, data, nextState) << "\n";
        out << mentorship_.mentorTeachingStyle() << "\n";
        out << mentorship_.learningPath() << "\n";
        out << mentorship_.teachBackRoutine() << "\n";
        out << mentorship_.familyLessonPlan() << "\n";
        out << mentorship_.practiceDrills() << "\n";
        out << mentorship_.nextGenerationStewardship() << "\n";
        out << mentorship_.mentorshipBoundaries();
        return out.str();
    }

    if (text.find("adaptive profile") != std::string::npos
        || text.find("adaptive guardian") != std::string::npos
        || text.find("adaptable") != std::string::npos
        || text.find("aware mode") != std::string::npos
        || text.find("aware") != std::string::npos
        || text.find("awareness profile") != std::string::npos
        || text.find("emotional") != std::string::npos
        || text.find("emotional support") != std::string::npos
        || text.find("emotionally supportive") != std::string::npos
        || text.find("tactical") != std::string::npos
        || text.find("tactical guardian") != std::string::npos
        || text.find("guardian tactics") != std::string::npos
        || text.find("helpful") != std::string::npos
        || text.find("helpful mode") != std::string::npos
        || text.find("personality profile") != std::string::npos) {
        out << "Adaptive guardian profile response\n";
        out << confidence_.confidenceForCommand(data.ownerCommand, data, nextState) << "\n";
        out << personality_.personalityProfile() << "\n";
        out << personality_.adaptiveAwarenessProfile() << "\n";
        out << personality_.emotionalSupportProfile() << "\n";
        out << personality_.nonViolentTacticalProfile() << "\n";
        out << personality_.helpfulnessProfile() << "\n";
        out << personality_.voiceStyleGuide() << "\n";
        out << personality_.privacyAndTrustGuide();
        return out.str();
    }

    if (text.find("private storage") != std::string::npos
        || text.find("encrypted storage") != std::string::npos
        || text.find("sensitive file") != std::string::npos
        || text.find("sensitive files") != std::string::npos
        || text.find("storage manifest") != std::string::npos
        || text.find("protect files") != std::string::npos
        || text.find("protect private files") != std::string::npos
        || text.find("file privacy") != std::string::npos) {
        out << "Private storage response\n";
        out << confidence_.confidenceForCommand(data.ownerCommand, data, nextState) << "\n";
        out << privateStorage_.storageStatus(data) << "\n";
        out << privateStorage_.sensitiveFilePolicy() << "\n";
        out << privateStorage_.futureEncryptionPlan() << "\n";
        out << privateStorage_.buildStorageManifest(data);
        return out.str();
    }

    if (text.find("thermal") != std::string::npos
        || text.find("infrared") != std::string::npos
        || text.find("ir sensor") != std::string::npos
        || text.find("ir camera") != std::string::npos
        || text.find("heat signature") != std::string::npos) {
        out << "IR and thermal sensor response\n";
        out << confidence_.confidenceForCommand(data.ownerCommand, data, nextState) << "\n";
        out << "Thermal camera: " << (data.thermalCameraOk ? "OK" : "not verified")
            << ", thermal calibrated: " << (data.thermalCameraCalibrated ? "yes" : "not yet")
            << ", thermal signature: " << (data.thermalSignatureDetected ? "detected" : "not detected")
            << ", thermal hotspot: " << (data.thermalHotspotDetected ? "detected" : "not detected") << ".\n";
        out << "Infrared sensor: " << (data.infraredSensorOk ? "OK" : "not verified")
            << ", infrared calibrated: " << (data.infraredSensorCalibrated ? "yes" : "not yet")
            << ", IR motion: " << (data.infraredMotionDetected ? "detected" : "not detected")
            << ", IR heat signature: " << (data.infraredHeatSignatureDetected ? "detected" : "not detected") << ".\n";
        out << threat_.environmentalCueSummary(data) << "\n";
        out << threat_.avoidanceRecommendation(data) << "\n";
        out << hardware_.sensorCheckReport(data) << "\n";
        out << "Privacy and ethics: use IR/thermal only for safety awareness, fire/heat risk, owner/family support, animal avoidance, and rescue cues. Do not use it for stalking, intimidation, hidden surveillance, or harassment.";
        return out.str();
    }

    if (text.find("memory") != std::string::npos
        || text.find("save memory") != std::string::npos
        || text.find("load memory") != std::string::npos) {
        out << "Memory status\n";
        out << persistentMemory_.memoryPolicy() << "\n";
        out << "Use saveMemory(filePath) to write a private memory snapshot, and loadMemoryPreview(filePath) to read it for review before trusting it.\n";
        out << "Current memory snapshot would include state " << toString(nextState)
            << ", location " << (data.locationKnown ? data.locationDescription : "unknown")
            << ", safe zone, camp memory, recent reports, action count, and audit count.\n";
        out << authPrompts_.authenticationPrompt(data);
        return out.str();
    }

    if (text.find("save inventory") != std::string::npos
        || text.find("load inventory") != std::string::npos
        || text.find("personal inventory") != std::string::npos) {
        out << "Personal inventory memory\n";
        out << personalInventory_.inventoryPolicy() << "\n";
        out << "Use saveInventory(filePath) to write the owner/family inventory archive, and loadInventoryPreview(filePath) to review a saved inventory before trusting it.\n";
        out << personalInventory_.buildInventoryArchive(data);
        return out.str();
    }

    if (text.find("owner profile") != std::string::npos
        || text.find("family profile") != std::string::npos
        || text.find("care profile") != std::string::npos
        || text.find("medical notes") != std::string::npos
        || text.find("allergies") != std::string::npos
        || text.find("safe words") != std::string::npos
        || text.find("safe word") != std::string::npos) {
        out << "Owner profile response\n";
        out << confidence_.confidenceForCommand(data.ownerCommand, data, nextState) << "\n";
        out << ownerProfile_.buildOwnerProfile(data) << "\n";
        out << ownerProfile_.emergencyCareCard(data);
        return out.str();
    }

    if (text.find("local knowledge") != std::string::npos
        || text.find("knowledge pack") != std::string::npos
        || text.find("toxic lookalikes") != std::string::npos
        || text.find("water advisories") != std::string::npos
        || text.find("land rules") != std::string::npos
        || text.find("local rules") != std::string::npos
        || text.find("local fishing rules") != std::string::npos) {
        out << "Local knowledge pack response\n";
        out << confidence_.confidenceForCommand(data.ownerCommand, data, nextState) << "\n";
        out << localKnowledge_.buildKnowledgePack(data);
        return out.str();
    }

    if (text.find("geofence") != std::string::npos
        || text.find("no-go") != std::string::npos
        || text.find("no go") != std::string::npos
        || text.find("safe zones") != std::string::npos
        || text.find("map plan") != std::string::npos
        || text.find("evacuation route") != std::string::npos) {
        out << "Map and geofence response\n";
        out << confidence_.confidenceForCommand(data.ownerCommand, data, nextState) << "\n";
        out << mapGeofence_.buildMapPlan(data);
        return out.str();
    }

    if (text.find("local area") != std::string::npos
        || text.find("area profile") != std::string::npos
        || text.find("local profile") != std::string::npos
        || text.find("region profile") != std::string::npos
        || text.find("emergency contacts") != std::string::npos
        || text.find("nearest help") != std::string::npos
        || text.find("local hazards") != std::string::npos) {
        out << "Local area profile response\n";
        out << confidence_.confidenceForCommand(data.ownerCommand, data, nextState) << "\n";
        out << localAreaProfile_.buildLocalAreaProfile(data);
        return out.str();
    }

    if (text.find("offline library") != std::string::npos
        || text.find("library index") != std::string::npos
        || text.find("manuals index") != std::string::npos
        || text.find("manuals") != std::string::npos
        || text.find("maps") != std::string::npos
        || text.find("field notes") != std::string::npos) {
        out << "Offline library index response\n";
        out << confidence_.confidenceForCommand(data.ownerCommand, data, nextState) << "\n";
        out << offlineLibrary_.buildLibraryIndex(data);
        return out.str();
    }

    if (text.find("driver interface") != std::string::npos
        || text.find("driver interfaces") != std::string::npos
        || text.find("controller interface") != std::string::npos
        || text.find("controller interfaces") != std::string::npos
        || text.find("fake controller") != std::string::npos
        || text.find("fake controllers") != std::string::npos
        || text.find("fake control") != std::string::npos
        || text.find("fake gps driver") != std::string::npos
        || text.find("fake imu driver") != std::string::npos
        || text.find("imu driver") != std::string::npos
        || text.find("compass driver") != std::string::npos
        || text.find("camera driver") != std::string::npos
        || text.find("smoke weather driver") != std::string::npos
        || text.find("weather driver") != std::string::npos
        || text.find("battery driver") != std::string::npos
        || text.find("solar charge driver") != std::string::npos
        || text.find("water filter driver") != std::string::npos
        || text.find("food storage driver") != std::string::npos
        || text.find("communication driver") != std::string::npos
        || text.find("owner alert driver") != std::string::npos
        || text.find("geofence driver") != std::string::npos
        || text.find("payload driver") != std::string::npos
        || text.find("medical request driver") != std::string::npos
        || text.find("obstacle driver") != std::string::npos
        || text.find("emergency stop driver") != std::string::npos
        || text.find("motor driver") != std::string::npos
        || text.find("steering driver") != std::string::npos
        || text.find("light speaker driver") != std::string::npos
        || text.find("motion controller") != std::string::npos
        || text.find("steering controller") != std::string::npos
        || text.find("power controller") != std::string::npos
        || text.find("bms controller") != std::string::npos
        || text.find("solar controller") != std::string::npos
        || text.find("owner auth controller") != std::string::npos
        || text.find("alert controller") != std::string::npos
        || text.find("navigation controller") != std::string::npos
        || text.find("sensor fusion controller") != std::string::npos
        || text.find("real driver class") != std::string::npos
        || text.find("real controller class") != std::string::npos) {
        out << "Hardware driver interface response\n";
        out << confidence_.confidenceForCommand(data.ownerCommand, data, nextState) << "\n";
        out << driverInterfaces_.fakeDriverStatusReport(data) << "\n";
        out << driverInterfaces_.fakeSensorReadings(data) << "\n";
        out << driverInterfaces_.fakeActuatorOutputs(data) << "\n";
        out << driverInterfaces_.fakeControllerStatusReport(data) << "\n";
        out << driverInterfaces_.fakeControllerOutputs(data) << "\n";
        out << driverInterfaces_.realDriverClassPlan() << "\n";
        out << driverInterfaces_.realControllerClassPlan() << "\n";
        out << driverInterfaces_.driverSwapChecklist() << "\n";
        out << driverInterfaces_.controllerSwapChecklist();
        return out.str();
    }

    if (text.find("hardware check") != std::string::npos
        || text.find("sensor check") != std::string::npos
        || text.find("sensor status") != std::string::npos
        || text.find("hardware interface") != std::string::npos
        || text.find("real hardware") != std::string::npos
        || text.find("motor check") != std::string::npos
        || text.find("actuator check") != std::string::npos
        || text.find("failsafe") != std::string::npos
        || text.find("emergency stop") != std::string::npos) {
        out << "Hardware interface and sensor check\n";
        out << confidence_.confidenceForCommand(data.ownerCommand, data, nextState) << "\n";
        out << hardware_.interfaceOverview(data) << "\n";
        out << hardware_.requiredInputsAndOutputs() << "\n";
        out << hardware_.sensorCheckReport(data) << "\n";
        out << hardware_.actuatorCheckReport(data) << "\n";
        out << hardware_.failsafeCheckReport(data) << "\n";
        out << hardware_.fieldTestSequence() << "\n";
        out << hardware_.readinessDecision(data);
        return out.str();
    }

    if (text.find("calibrate") != std::string::npos
        || text.find("calibration") != std::string::npos
        || text.find("test gps") != std::string::npos
        || text.find("test obstacle") != std::string::npos
        || text.find("test owner alert") != std::string::npos
        || text.find("test battery monitor") != std::string::npos) {
        out << "Calibration response\n";
        out << confidence_.confidenceForCommand(data.ownerCommand, data, nextState) << "\n";
        out << calibration_.calibrationReport(data) << "\n";
        out << calibration_.sensorCalibrationChecklist() << "\n";
        out << calibration_.actuatorCalibrationChecklist();
        return out.str();
    }

    if (text.find("hardware adapter") != std::string::npos
        || text.find("adapter interface") != std::string::npos
        || text.find("gps adapter") != std::string::npos
        || text.find("motor adapter") != std::string::npos) {
        out << "Hardware adapter interface response\n";
        out << confidence_.confidenceForCommand(data.ownerCommand, data, nextState) << "\n";
        out << hardwareAdapters_.adapterOverview() << "\n";
        out << hardwareAdapters_.sensorAdapters() << "\n";
        out << hardwareAdapters_.actuatorAdapters() << "\n";
        out << hardwareAdapters_.adapterSafetyContract();
        return out.str();
    }

    if (text.find("voice") != std::string::npos
        || text.find("phone") != std::string::npos
        || text.find("private alert") != std::string::npos) {
        out << "Voice and phone interface response\n";
        out << confidence_.confidenceForCommand(data.ownerCommand, data, nextState) << "\n";
        out << voicePhone_.interfacePlan(data) << "\n";
        out << voicePhone_.commandSafetyRules() << "\n";
        out << voicePhone_.privateAlertPlan() << "\n";
        out << voicePhone_.offlineFallbackPlan();
        return out.str();
    }

    if (text.find("hardware stub") != std::string::npos
        || text.find("stub layer") != std::string::npos
        || text.find("simulated hardware") != std::string::npos
        || text.find("fake sensor") != std::string::npos
        || text.find("fake actuator") != std::string::npos
        || text.find("simulated output") != std::string::npos
        || text.find("real adapter swap") != std::string::npos) {
        const HardwareSensorFrame frame = hardwareStubs_.buildSensorFrame(data);
        const HardwareOutputCommand command = hardwareStubs_.plannedOutputForState(nextState, data);
        out << "Hardware stub layer response\n";
        out << confidence_.confidenceForCommand(data.ownerCommand, data, nextState) << "\n";
        out << hardwareStubs_.sensorFrameReport(frame) << "\n";
        out << hardwareStubs_.outputCommandReport(command) << "\n";
        out << hardwareStubs_.stubSafetyContract() << "\n";
        out << hardwareStubs_.realAdapterSwapPlan();
        return out.str();
    }

    if (text.find("driver interface") != std::string::npos
        || text.find("driver interfaces") != std::string::npos
        || text.find("fake gps driver") != std::string::npos
        || text.find("fake imu driver") != std::string::npos
        || text.find("imu driver") != std::string::npos
        || text.find("compass driver") != std::string::npos
        || text.find("camera driver") != std::string::npos
        || text.find("smoke weather driver") != std::string::npos
        || text.find("weather driver") != std::string::npos
        || text.find("battery driver") != std::string::npos
        || text.find("solar charge driver") != std::string::npos
        || text.find("water filter driver") != std::string::npos
        || text.find("food storage driver") != std::string::npos
        || text.find("communication driver") != std::string::npos
        || text.find("owner alert driver") != std::string::npos
        || text.find("geofence driver") != std::string::npos
        || text.find("payload driver") != std::string::npos
        || text.find("medical request driver") != std::string::npos
        || text.find("obstacle driver") != std::string::npos
        || text.find("emergency stop driver") != std::string::npos
        || text.find("motor driver") != std::string::npos
        || text.find("steering driver") != std::string::npos
        || text.find("light speaker driver") != std::string::npos
        || text.find("real driver class") != std::string::npos) {
        out << "Hardware driver interface response\n";
        out << confidence_.confidenceForCommand(data.ownerCommand, data, nextState) << "\n";
        out << driverInterfaces_.fakeDriverStatusReport(data) << "\n";
        out << driverInterfaces_.fakeSensorReadings(data) << "\n";
        out << driverInterfaces_.fakeActuatorOutputs(data) << "\n";
        out << driverInterfaces_.realDriverClassPlan() << "\n";
        out << driverInterfaces_.driverSwapChecklist();
        return out.str();
    }

    if (text.find("driver bridge") != std::string::npos
        || text.find("driver status") != std::string::npos
        || text.find("sensor driver") != std::string::npos
        || text.find("actuator driver") != std::string::npos
        || text.find("output gate") != std::string::npos
        || text.find("driver fault") != std::string::npos) {
        out << "Hardware driver bridge response\n";
        out << confidence_.confidenceForCommand(data.ownerCommand, data, nextState) << "\n";
        out << driverBridge_.driverBridgeOverview(data) << "\n";
        out << driverBridge_.sensorDriverContract() << "\n";
        out << driverBridge_.actuatorDriverContract() << "\n";
        out << driverBridge_.safeOutputGate(data);
        return out.str();
    }

    if (text.find("owner dashboard") != std::string::npos
        || text.find("dashboard") != std::string::npos) {
        out << "Owner dashboard response\n";
        out << confidence_.confidenceForCommand(data.ownerCommand, data, nextState) << "\n";
        out << ownerDashboard_.buildDashboardSnapshot(
            nextState,
            data,
            countSituationReports(reportLog_),
            actionLog_.size(),
            audit_.entries().size());
        return out.str();
    }

    if (text.find("field test") != std::string::npos
        || text.find("walk test") != std::string::npos
        || text.find("idle distance test") != std::string::npos
        || text.find("retreat route test") != std::string::npos
        || text.find("false alarm") != std::string::npos) {
        out << "Field test protocol response\n";
        out << confidence_.confidenceForCommand(data.ownerCommand, data, nextState) << "\n";
        out << fieldTests_.testStatusReport(data) << "\n";
        out << fieldTests_.benchTestProtocol() << "\n";
        out << fieldTests_.controlledWalkTestProtocol() << "\n";
        out << fieldTests_.falseAlarmReviewProtocol() << "\n";
        out << fieldTests_.fieldDeploymentDecision(data);
        return out.str();
    }

    if (text.find("access control") != std::string::npos
        || text.find("key status") != std::string::npos
        || text.find("trusted controller") != std::string::npos
        || text.find("tamper") != std::string::npos
        || text.find("private log protection") != std::string::npos) {
        out << "Security access response\n";
        out << confidence_.confidenceForCommand(data.ownerCommand, data, nextState) << "\n";
        out << securityAccess_.accessStatus(data) << "\n";
        out << securityAccess_.commandPermissionMatrix() << "\n";
        out << securityAccess_.tamperAndOutsiderResponse(data) << "\n";
        out << securityAccess_.privateLogProtection(data);
        return out.str();
    }

    if (text.find("real world readiness") != std::string::npos
        || text.find("real-world readiness") != std::string::npos
        || text.find("real world deployment") != std::string::npos
        || text.find("deployment gate") != std::string::npos
        || text.find("what is missing") != std::string::npos
        || text.find("what are we missing") != std::string::npos
        || text.find("missing items") != std::string::npos) {
        out << "Real-world deployment gate response\n";
        out << confidence_.confidenceForCommand(data.ownerCommand, data, nextState) << "\n";
        out << realWorldDeployment_.realWorldChecklist(data) << "\n";
        out << fieldReadiness_.readinessReport(data) << "\n";
        out << safetyValidation_.preFieldUseGate();
        return out.str();
    }

    if (text.find("field readiness") != std::string::npos
        || text.find("readiness score") != std::string::npos
        || text.find("deployment readiness") != std::string::npos
        || text.find("are you ready") != std::string::npos) {
        out << "Field readiness response\n";
        out << confidence_.confidenceForCommand(data.ownerCommand, data, nextState) << "\n";
        out << fieldReadiness_.readinessReport(data) << "\n";
        out << realWorldDeployment_.deploymentGate(data) << "\n";
        out << hardware_.readinessDecision(data) << "\n";
        out << safetyValidation_.preFieldUseGate();
        return out.str();
    }

    if (text.find("validation") != std::string::npos
        || text.find("safety validation") != std::string::npos
        || text.find("test checklist") != std::string::npos
        || text.find("pre field") != std::string::npos
        || text.find("pre-field") != std::string::npos
        || text.find("field ready") != std::string::npos
        || text.find("hardware readiness") != std::string::npos) {
        out << "Safety validation response\n";
        out << confidence_.confidenceForCommand(data.ownerCommand, data, nextState) << "\n";
        out << safetyValidation_.validationOverview() << "\n";
        out << safetyValidation_.missionSafetyChecklist() << "\n";
        out << safetyValidation_.behaviorTestChecklist() << "\n";
        out << safetyValidation_.medicalAndEmergencyChecklist() << "\n";
        out << safetyValidation_.electricalGeneratorChecklist() << "\n";
        out << safetyValidation_.wildlifeConservationChecklist() << "\n";
        out << safetyValidation_.hardwareReadinessChecklist() << "\n";
        out << safetyValidation_.preFieldUseGate();
        return out.str();
    }

    if (text.find("solar charge") != std::string::npos
        || text.find("solar charging") != std::string::npos
        || text.find("solar panel") != std::string::npos
        || text.find("solar battery") != std::string::npos
        || text.find("charge controller") != std::string::npos
        || text.find("overcharge") != std::string::npos
        || text.find("over charge") != std::string::npos
        || text.find("overcurrent") != std::string::npos
        || text.find("over current") != std::string::npos
        || text.find("float charge") != std::string::npos
        || text.find("charging disconnect") != std::string::npos
        || text.find("panel charging") != std::string::npos
        || text.find("water filter") != std::string::npos
        || text.find("filter water") != std::string::npos
        || text.find("filtered water") != std::string::npos
        || text.find("clean water storage") != std::string::npos
        || text.find("water storage") != std::string::npos
        || text.find("dry food") != std::string::npos
        || text.find("food drying") != std::string::npos
        || text.find("food dehydration") != std::string::npos
        || text.find("dehydrate") != std::string::npos
        || text.find("dehydrator") != std::string::npos
        || text.find("food storage") != std::string::npos
        || text.find("dry storage") != std::string::npos
        || text.find("pantry") != std::string::npos
        || text.find("preserve food") != std::string::npos
        || text.find("food preservation") != std::string::npos) {
        out << "Solar charging, water filtering, and food storage guidance\n";
        out << confidence_.confidenceForCommand(data.ownerCommand, data, nextState) << "\n";
        out << solarCharging_.status(data) << "\n";
        out << calculators_.solarHarvestEstimate(data) << "\n";
        out << solarCharging_.fieldChargingPlan(data) << "\n";
        out << solarCharging_.overchargeProtectionStatus(data) << "\n";
        out << solarCharging_.teachingGuide() << "\n";
        out << solarCharging_.essentialLoadPriority() << "\n";
        out << solarCharging_.safetyBoundary() << "\n";
        out << "Water filter status: " << (data.waterFilterAvailable ? "available" : "not confirmed")
            << ", clean water containers: " << (data.cleanWaterContainersAvailable ? "available" : "not confirmed") << ".\n";
        out << water_.filtrationTeachingGuide() << "\n";
        out << water_.purificationGuidance() << "\n";
        out << water_.storageHygieneGuide() << "\n";
        out << foodPreservation_.dryingBasics() << "\n";
        out << foodPreservation_.storageBasics(data) << "\n";
        out << foodPreservation_.pantryRotationGuide() << "\n";
        out << foodPreservation_.preservationSafetyBoundary();
        return out.str();
    }

    if (text.find("calculator") != std::string::npos
        || text.find("calculate") != std::string::npos
        || text.find("runtime") != std::string::npos
        || text.find("run time") != std::string::npos
        || text.find("watt") != std::string::npos
        || text.find("solar estimate") != std::string::npos
        || text.find("generator load") != std::string::npos
        || text.find("water days") != std::string::npos
        || text.find("rain catch") != std::string::npos
        || text.find("rainwater") != std::string::npos
        || text.find("garden spacing") != std::string::npos) {
        out << "Field calculator response\n";
        out << confidence_.confidenceForCommand(data.ownerCommand, data, nextState) << "\n";
        out << calculators_.calculatorSummary(data) << "\n";
        out << maintenance_.nextMaintenancePriorities(data);
        return out.str();
    }

    if (text.find("maintenance") != std::string::npos
        || text.find("schedule") != std::string::npos
        || text.find("service") != std::string::npos
        || text.find("weekly checklist") != std::string::npos
        || text.find("monthly checklist") != std::string::npos
        || text.find("seasonal checklist") != std::string::npos
        || text.find("emergency reset") != std::string::npos
        || text.find("winterize") != std::string::npos
        || text.find("fire season") != std::string::npos
        || text.find("readiness") != std::string::npos) {
        out << "Maintenance schedule response\n";
        out << confidence_.confidenceForCommand(data.ownerCommand, data, nextState) << "\n";
        out << maintenance_.maintenanceOverview(data) << "\n";
        out << maintenance_.weeklyChecklist() << "\n";
        out << maintenance_.monthlyChecklist() << "\n";
        out << maintenance_.seasonalChecklist(data) << "\n";
        out << maintenance_.emergencyResetChecklist();
        return out.str();
    }

    if (text.find("make tools") != std::string::npos
        || text.find("make tool") != std::string::npos
        || text.find("tools from resources") != std::string::npos
        || text.find("tool from resources") != std::string::npos
        || text.find("resource tools") != std::string::npos
        || text.find("resource tool") != std::string::npos
        || text.find("field tool") != std::string::npos
        || text.find("toolmaking") != std::string::npos) {
        out << "Safe toolmaking from resources\n";
        out << confidence_.confidenceForCommand(data.ownerCommand, data, nextState) << "\n";
        out << makerProjects_.resourceToolmakingGuide() << "\n";
        out << makerProjects_.fieldToolIdeasFromResources() << "\n";
        out << aquatic_.survivalFishingGearGuide() << "\n";
        out << inventoryPlanner_.inventorySummary(data) << "\n";
        out << resourcefulness_.safeSubstitutionGuide() << "\n";
        out << makerProjects_.toolAndWorkshopSafety() << "\n";
        out << makerProjects_.toolmakingSafetyBoundary() << "\n";
        out << inventoryPlanner_.doNotBuildWarnings(data);
        return out.str();
    }

    if (!fishingSpecificCommand
        && (text.find("project planner") != std::string::npos
        || text.find("project plan") != std::string::npos
        || text.find("parts list") != std::string::npos
        || text.find("parts inventory") != std::string::npos
        || text.find("available parts") != std::string::npos
        || text.find("tool inventory") != std::string::npos
        || text.find("make tools") != std::string::npos
        || text.find("make tool") != std::string::npos
        || text.find("tools from resources") != std::string::npos
        || text.find("tool from resources") != std::string::npos
        || text.find("resource tools") != std::string::npos
        || text.find("resource tool") != std::string::npos
        || text.find("field tool") != std::string::npos
        || text.find("toolmaking") != std::string::npos
        || text.find("project goal") != std::string::npos
        || text.find("what can i make") != std::string::npos
        || text.find("what can we make") != std::string::npos
        || text.find("what can i build") != std::string::npos
        || text.find("what can we build") != std::string::npos
        || text.find("project log") != std::string::npos)) {
        out << "Inventory and project planner\n";
        out << confidence_.confidenceForCommand(data.ownerCommand, data, nextState) << "\n";
        out << inventoryPlanner_.inventorySummary(data) << "\n";
        out << inventoryPlanner_.projectPlanner(data) << "\n";
        out << inventoryPlanner_.safeBuildIdeas(data) << "\n";
        out << aquatic_.survivalFishingGearGuide() << "\n";
        out << inventoryPlanner_.doNotBuildWarnings(data) << "\n";
        out << inventoryPlanner_.projectLogTemplate();
        return out.str();
    }

    if (text.find("resourceful") != std::string::npos
        || text.find("resourcefulness") != std::string::npos
        || text.find("inventory") != std::string::npos
        || text.find("safe substitute") != std::string::npos
        || text.find("substitute") != std::string::npos
        || text.find("improvise") != std::string::npos
        || text.find("improvisation") != std::string::npos
        || text.find("repurpose") != std::string::npos
        || text.find("scavenge") != std::string::npos
        || text.find("spare parts") != std::string::npos
        || text.find("what can we reuse") != std::string::npos
        || text.find("ration") != std::string::npos) {
        out << "Resourcefulness plan\n";
        out << confidence_.confidenceForCommand(data.ownerCommand, data, nextState) << "\n";
        out << resourcefulness_.resourcefulnessMindset() << "\n";
        out << resourcefulness_.inventoryAndTriageGuide(data) << "\n";
        out << inventoryPlanner_.inventorySummary(data) << "\n";
        out << makerProjects_.resourceToolmakingGuide() << "\n";
        out << makerProjects_.fieldToolIdeasFromResources() << "\n";
        out << aquatic_.survivalFishingGearGuide() << "\n";
        out << resourcefulness_.safeSubstitutionGuide() << "\n";
        out << resourcefulness_.fieldRepairGuide() << "\n";
        out << resourcefulness_.ruralSkillMap() << "\n";
        out << resourcefulness_.ethicalBoundaries() << "\n";
        out << ruralSustainability_.resiliencePriorities();
        return out.str();
    }

    if (text.find("generator") != std::string::npos
        || text.find("alternator") != std::string::npos
        || text.find("turbine") != std::string::npos
        || text.find("wind power") != std::string::npos
        || text.find("water wheel") != std::string::npos
        || text.find("micro hydro") != std::string::npos) {
        out << "Mini-generator and energy project guidance\n";
        out << confidence_.confidenceForCommand(data.ownerCommand, data, nextState) << "\n";
        out << makerProjects_.miniGeneratorLearningPath() << "\n";
        out << electricalSafety_.generatorSafetyBoundaries() << "\n";
        out << electricalSafety_.batteryAndStorageSafety() << "\n";
        out << electricalSafety_.gridAndMainsBoundary() << "\n";
        out << ruralSustainability_.resiliencePriorities();
        return out.str();
    }

    if (text.find("electrical") != std::string::npos
        || text.find("wiring") != std::string::npos
        || text.find("low voltage") != std::string::npos
        || text.find("battery bank") != std::string::npos
        || text.find("solar") != std::string::npos
        || text.find("inverter") != std::string::npos) {
        out << "Electrical learning and safety guidance\n";
        out << confidence_.confidenceForCommand(data.ownerCommand, data, nextState) << "\n";
        out << electricalSafety_.electricalSafetyRules() << "\n";
        out << electricalSafety_.lowVoltageLearningPlan() << "\n";
        out << electricalSafety_.batteryAndStorageSafety() << "\n";
        out << electricalSafety_.gridAndMainsBoundary();
        return out.str();
    }

    if (text.find("rural") != std::string::npos
        || text.find("self sustain") != std::string::npos
        || text.find("self-sustain") != std::string::npos
        || text.find("off grid") != std::string::npos
        || text.find("off-grid") != std::string::npos
        || text.find("homestead") != std::string::npos) {
        out << "Rural self-sustainability guidance\n";
        out << ruralSustainability_.selfReliancePlan() << "\n";
        out << ruralSustainability_.ruralSystemsChecklist() << "\n";
        out << ruralSustainability_.maintenanceRhythm() << "\n";
        out << resourcefulness_.ruralSkillMap() << "\n";
        out << ruralSustainability_.resiliencePriorities();
        return out.str();
    }

    if (!fishingSpecificCommand
        && (text.find("diy") != std::string::npos
        || text.find("project") != std::string::npos
        || text.find("make") != std::string::npos
        || text.find("build") != std::string::npos
        || text.find("repair") != std::string::npos
        || text.find("old parts") != std::string::npos
        || text.find("salvage") != std::string::npos
        || text.find("reuse") != std::string::npos)) {
        out << "DIY maker and repair guidance\n";
        out << makerProjects_.diyProjectPlanningGuide() << "\n";
        out << makerProjects_.salvageReuseGuide() << "\n";
        out << makerProjects_.resourceToolmakingGuide() << "\n";
        out << makerProjects_.fieldToolIdeasFromResources() << "\n";
        out << aquatic_.survivalFishingGearGuide() << "\n";
        out << resourcefulness_.safeSubstitutionGuide() << "\n";
        out << resourcefulness_.fieldRepairGuide() << "\n";
        out << makerProjects_.toolAndWorkshopSafety() << "\n";
        out << makerProjects_.toolmakingSafetyBoundary() << "\n";
        out << makerProjects_.practicalProjectIdeas() << "\n";
        out << electricalSafety_.electricalSafetyRules();
        return out.str();
    }

    if (text.find("scenario") != std::string::npos
        || text.find("simulator") != std::string::npos
        || text.find("test menu") != std::string::npos) {
        out << scenarios_.scenarioMenu();
        return out.str();
    }

    if (text.find("weather") != std::string::npos
        || text.find("storm") != std::string::npos
        || text.find("heat risk") != std::string::npos
        || text.find("cold risk") != std::string::npos
        || text.find("fire or smoke") != std::string::npos) {
        out << "Weather status: temperature " << data.temperatureC << " C, heat index " << data.heatIndexC
            << " C, humidity " << data.humidityPercent << "%, wind " << data.windKph << " kph.\n";
        out << weather_.safetyAdvice(data) << "\n";
        out << "Weather trend: " << weather_.trendAwareness(data, previousData_) << "\n";
        out << confidence_.confidenceForCommand(data.ownerCommand, data, nextState) << "\n";
        out << observationPrompts_.weatherQuestions() << "\n";
        out << "Best judgment: " << importantReports_.bestJudgment(data, nextState);
        return out.str();
    }

    if (text.find("medical") != std::string::npos
        || text.find("first aid") != std::string::npos
        || text.find("vitals") != std::string::npos
        || text.find("shock") != std::string::npos) {
        const InjurySeverity severity = medic_.assessInjury(data);
        out << "Medical status: assessed injury severity is " << toString(severity) << ".\n";
        out << medic_.supportiveMessage() << "\n";
        out << medic_.vitalsPrompt() << "\n";
        out << confidence_.confidenceForCommand(data.ownerCommand, data, nextState) << "\n";
        out << observationPrompts_.medicalQuestions() << "\n";
        out << medic_.firstAidGuidance(severity);
        return out.str();
    }

    if (!fishingSpecificCommand
        && (text.find("resource") != std::string::npos
        || text.find("battery") != std::string::npos
        || text.find("energy") != std::string::npos
        || text.find("survival") != std::string::npos
        || text.find("water and food") != std::string::npos)) {
        out << "Resource status: " << resources_.resourceSummary(data) << "\n";
        out << resourcefulness_.inventoryAndTriageGuide(data) << "\n";
        out << calculators_.batteryRuntimeEstimate(data) << "\n";
        out << solarCharging_.status(data) << "\n";
        out << calculators_.solarHarvestEstimate(data) << "\n";
        out << solarCharging_.overchargeProtectionStatus(data) << "\n";
        out << solarCharging_.essentialLoadPriority() << "\n";
        out << calculators_.waterDurationEstimate(data) << "\n";
        out << water_.filtrationTeachingGuide() << "\n";
        out << foodPreservation_.storageBasics(data) << "\n";
        out << aquatic_.survivalFishingGearGuide() << "\n";
        out << aquatic_.emergencyFoodGuidance() << "\n";
        out << energySaving_.criticalFunctionPlan(data) << "\n";
        out << energySaving_.sensorFrequencyPlan(data) << "\n";
        out << energySaving_.movementConservationPlan(data) << "\n";
        out << energySaving_.essentialTaskPlan(data);
        return out.str();
    }

    if (text.find("bushcraft") != std::string::npos
        || text.find("campcraft") != std::string::npos
        || text.find("fire safety") != std::string::npos
        || text.find("campfire") != std::string::npos
        || text.find("warmth") != std::string::npos
        || text.find("knots") != std::string::npos
        || text.find("cordage") != std::string::npos
        || text.find("basket making") != std::string::npos
        || text.find("basket weaving") != std::string::npos
        || text.find("lashings") != std::string::npos
        || text.find("lashing") != std::string::npos
        || text.find("tarp line") != std::string::npos
        || text.find("tent line") != std::string::npos
        || text.find("tent hanging") != std::string::npos
        || text.find("hang tent") != std::string::npos
        || text.find("hanging tent") != std::string::npos
        || text.find("guy line") != std::string::npos
        || text.find("ridgeline") != std::string::npos
        || text.find("tool safety") != std::string::npos
        || text.find("tool use") != std::string::npos
        || text.find("carving") != std::string::npos
        || text.find("camp hygiene") != std::string::npos
        || text.find("camp sanitation") != std::string::npos
        || text.find("sanitation") != std::string::npos
        || text.find("trailcraft") != std::string::npos
        || text.find("camp cooking") != std::string::npos
        || text.find("low impact") != std::string::npos
        || text.find("low-impact") != std::string::npos
        || text.find("leave no trace") != std::string::npos) {
        out << "Bushcraft skills response\n";
        out << confidence_.confidenceForCommand(data.ownerCommand, data, nextState) << "\n";
        out << bushcraft_.emergencyPriorities() << "\n";
        out << bushcraft_.shelterTechniques(data.terrain) << "\n";
        out << bushcraft_.fireSafetyAndWarmth() << "\n";
        out << bushcraft_.knotsAndCordage() << "\n";
        out << bushcraft_.toolUseAndCarvingSafety() << "\n";
        out << bushcraft_.campHygieneAndSanitation() << "\n";
        out << bushcraft_.cookingAndFoodSafety() << "\n";
        out << bushcraft_.trailcraftAndNavigation() << "\n";
        out << bushcraft_.weatherClothingAndInsulation() << "\n";
        out << bushcraft_.signalingAndRescue() << "\n";
        out << bushcraft_.lowImpactBushcraft() << "\n";
        out << bushcraft_.bushcraftSafetyBoundary();
        return out.str();
    }

    if (text.find("fish") != std::string::npos
        || text.find("fishing") != std::string::npos
        || text.find("angling") != std::string::npos
        || text.find("aquatic") != std::string::npos
        || text.find("waterway") != std::string::npos
        || text.find("river") != std::string::npos
        || text.find("stream") != std::string::npos
        || text.find("lake") != std::string::npos
        || text.find("pond") != std::string::npos
        || text.find("shoreline") != std::string::npos) {
        out << "Fishing and aquatic conservation guide\n";
        out << confidence_.confidenceForCommand(data.ownerCommand, data, nextState) << "\n";
        out << observationPrompts_.aquaticQuestions() << "\n";
        out << aquatic_.fishingEthicsAndLaw() << "\n";
        out << aquatic_.fishBiologicalCategories() << "\n";
        out << aquatic_.fishFieldCategoryGuide() << "\n";
        out << aquatic_.fishIdentificationGuide() << "\n";
        out << aquatic_.survivalFishingGearGuide() << "\n";
        out << aquatic_.sustainableFishingGuidance() << "\n";
        out << aquatic_.aquaticHabitatProtection() << "\n";
        out << aquatic_.fishSafetyAndFoodHandling() << "\n";
        out << aquatic_.waterwaySafety() << "\n";
        out << aquatic_.emergencyFoodGuidance();
        return out.str();
    }

    if (text.find("water") != std::string::npos) {
        out << "Water status and guidance\n";
        out << water_.findWaterEthically(data.terrain) << "\n";
        out << water_.safeUsageAdvice() << "\n";
        out << water_.filtrationTeachingGuide() << "\n";
        out << water_.purificationGuidance() << "\n";
        out << water_.storageHygieneGuide();
        return out.str();
    }

    if (text.find("shelter") != std::string::npos
        || text.find("camp") != std::string::npos
        || text.find("safe rest") != std::string::npos) {
        out << "Shelter and camp status\n";
        out << bushcraft_.findShelter(data.terrain) << "\n";
        out << bushcraft_.chooseSafeRestArea(data) << "\n";
        out << bushcraft_.planCamp(data) << "\n";
        out << bushcraft_.shelterTechniques(data.terrain) << "\n";
        out << bushcraft_.campHygieneAndSanitation() << "\n";
        out << bushcraft_.lowImpactBushcraft() << "\n";
        out << bushcraft_.bushcraftSafetyBoundary();
        return out.str();
    }

    if (text.find("nomad") != std::string::npos
        || text.find("field guide") != std::string::npos) {
        out << "Nomad field guide response\n";
        out << confidence_.confidenceForCommand(data.ownerCommand, data, nextState) << "\n";
        out << observationPrompts_.nomadChecklist(data.terrain) << "\n";
        out << "Priority order: immediate safety, medical needs, weather/fire awareness, water, shelter, route, signaling, then food education.\n";
        out << "Route: " << threat_.avoidanceRecommendation(data) << "\n";
        out << "Weather: " << weather_.safetyAdvice(data) << " " << weather_.trendAwareness(data, previousData_) << "\n";
        out << "Water: " << water_.findWaterEthically(data.terrain) << " " << water_.purificationGuidance() << "\n";
        out << "Shelter: " << bushcraft_.chooseSafeRestArea(data) << "\n";
        out << "Bushcraft: " << bushcraft_.emergencyPriorities() << "\n";
        out << "Low impact campcraft: " << bushcraft_.lowImpactBushcraft() << "\n";
        out << "Plants: " << foraging_.safetyRules() << "\n";
        out << "Fishing: " << aquatic_.emergencyFoodGuidance() << "\n";
        out << "Fishing gear: " << aquatic_.survivalFishingGearGuide() << "\n";
        out << "Solar: " << solarCharging_.fieldChargingPlan(data) << "\n";
        out << "Food storage: " << foodPreservation_.pantryRotationGuide() << "\n";
        out << "Animals: " << animalEducation_.avoidProvokingAnimals() << "\n";
        out << "Stars: " << astronomy_.starGuidance() << "\n";
        out << "Signals: " << emergencyCommunication_.signalingGuidance();
        return out.str();
    }

    if (text.find("plant") != std::string::npos
        || text.find("tree") != std::string::npos
        || text.find("berry") != std::string::npos
        || text.find("mushroom") != std::string::npos
        || text.find("edible") != std::string::npos
        || text.find("poisonous") != std::string::npos
        || text.find("toxic") != std::string::npos
        || text.find("foraging") != std::string::npos) {
        out << "Plant and foraging field guide\n";
        out << confidence_.confidenceForCommand(data.ownerCommand, data, nextState) << "\n";
        out << observationPrompts_.plantQuestions(data.terrain) << "\n";
        out << "I cannot confirm an exact plant species from a vague question. Do not eat any wild plant unless identification is 100% certain from multiple features and a trusted local source.\n";
        out << "Observe: leaf arrangement, leaf edges, veins, stem shape, hairs/thorns, flowers, fruit, seed pods, sap, smell, habitat, season, and toxic lookalikes. Photograph rather than picking when possible.\n";
        out << foraging_.safetyRules() << "\n";
        out << foraging_.ethicalRules() << "\n";
        out << foraging_.regionGuidance(data.terrain) << "\n";
        out << foraging_.wildlifeInteractionRules();
        return out.str();
    }

    if (text.find("animal") != std::string::npos
        || text.find("wildlife") != std::string::npos
        || text.find("animal kingdom") != std::string::npos
        || text.find("insect") != std::string::npos
        || text.find("bug") != std::string::npos
        || text.find("bugs") != std::string::npos
        || text.find("arachnid") != std::string::npos
        || text.find("spider") != std::string::npos
        || text.find("tick") != std::string::npos
        || text.find("scorpion") != std::string::npos
        || text.find("reptile") != std::string::npos
        || text.find("amphibian") != std::string::npos
        || text.find("bird") != std::string::npos
        || text.find("mammal") != std::string::npos
        || text.find("track") != std::string::npos
        || text.find("scat") != std::string::npos) {
        out << "Animal kingdom and wildlife field guide\n";
        out << confidence_.confidenceForCommand(data.ownerCommand, data, nextState) << "\n";
        out << observationPrompts_.animalQuestions() << "\n";
        out << "I can help narrow clues, but exact animal or insect ID needs clear body features, tracks/signs, behavior, sound, habitat, season, time of day, and local species range. Observe from a distance and never follow signs toward dens, nests, webs, hives, or feeding sites.\n";
        out << animalEducation_.animalKingdomOverview() << "\n";
        out << animalEducation_.insectAndSmallAnimalGuide() << "\n";
        out << animalEducation_.safeIdentificationProcess() << "\n";
        out << animalEducation_.behaviorPatterns() << "\n";
        out << animalEducation_.tracksAndSigns() << "\n";
        out << animalEducation_.avoidProvokingAnimals() << "\n";
        out << animalEducation_.habitatAndConservationReminder() << "\n";
        out << wildlife_.ethicalInteractionAdvice(data) << "\n";
        out << wildlife_.nonHarmfulDeterrence(data) << "\n";
        out << animalTriage_.triageSummary(data) << "\n";
        out << animalTriage_.lifePriorityGuidance(data) << "\n";
        out << animalTriage_.ownerAssistanceGuidance(data) << "\n";
        out << animalTriage_.safeAnimalCareGuidance(data) << "\n";
        out << animalTriage_.escalationGuidance(data);
        return out.str();
    }

    if (text.find("privacy") != std::string::npos
        || text.find("security") != std::string::npos
        || text.find("ai") != std::string::npos
        || text.find("machine") != std::string::npos
        || text.find("authorized stop") != std::string::npos) {
        out << "Privacy and security status\n";
        out << privacy_.privacyDecision(data) << "\n";
        out << securityAccess_.accessStatus(data) << "\n";
        out << securityAccess_.commandPermissionMatrix() << "\n";
        out << securityAccess_.tamperAndOutsiderResponse(data) << "\n";
        out << securityAccess_.privateLogProtection(data) << "\n";
        out << aiContainment_.containmentPlan(data) << "\n";
        out << aiContainment_.authorizedStopPlan(data) << "\n";
        out << dangerousMachines_.immediateLifeSafetyPlan(data) << "\n";
        out << dangerousMachines_.authorizedDisablePlan(data) << "\n";
        out << ethicalPolicy_.corePrinciples();
        return out.str();
    }

    if (text.find("signal") != std::string::npos
        || text.find("rescue communication") != std::string::npos
        || text.find("emergency communication") != std::string::npos) {
        out << "Emergency communication status\n";
        out << emergencyCommunication_.signalingGuidance() << "\n";
        out << emergencyCommunication_.visibilityGuidance() << "\n";
        out << emergencyCommunication_.informationToConvey() << "\n";
        out << emergencyServices_.communicationPriority(data);
        if (emergencyServices_.shouldPrepareReport(data)) {
            out << "\n" << emergencyServices_.emergencyReport(data, nextState);
            out << "\n" << emergencyServices_.responderSafetyNotes(data);
        }
        return out.str();
    }

    if (text.find("star") != std::string::npos
        || text.find("stars") != std::string::npos
        || text.find("north star") != std::string::npos
        || text.find("polaris") != std::string::npos
        || text.find("constellation") != std::string::npos
        || text.find("follow stars") != std::string::npos
        || text.find("navigate by stars") != std::string::npos
        || text.find("astronomy") != std::string::npos) {
        out << "Stars and sky navigation field guide\n";
        out << confidence_.confidenceForCommand(data.ownerCommand, data, nextState) << "\n";
        out << observationPrompts_.astronomyQuestions() << "\n";
        out << "Use stars only as rough backup orientation. Do not travel into unsafe terrain, smoke, storms, cliffs, flood zones, or wildlife risk because of a sky cue.\n";
        out << astronomy_.sunGuidance() << "\n";
        out << astronomy_.starGuidance() << "\n";
        out << astronomy_.safetyReminder();
        return out.str();
    }

    if (text.find("rock") != std::string::npos
        || text.find("mineral") != std::string::npos
        || text.find("stone") != std::string::npos
        || text.find("volcanic") != std::string::npos) {
        out << "Rock and mineral field guide\n";
        out << confidence_.confidenceForCommand(data.ownerCommand, data, nextState) << "\n";
        out << observationPrompts_.rockQuestions() << "\n";
        out << "I can provide clues, not a guaranteed ID. Start with non-destructive observation and respect land ownership, habitat, protected areas, and unstable slopes.\n";
        out << landEducation_.mineralLesson() << "\n";
        out << landEducation_.volcanicRockLesson() << "\n";
        out << rockId_.heuristics() << "\n";
        out << rockId_.ethicalSamplingReminder();
        return out.str();
    }

    if (text.find("land") != std::string::npos
        || text.find("soil") != std::string::npos
        || text.find("farming") != std::string::npos
        || text.find("what kind of") != std::string::npos) {
        out << "Education command response\n";
        if (text.find("farming") != std::string::npos || text.find("soil") != std::string::npos) {
            out << farming_.soilAssessment(data.terrain) << "\n" << farming_.soilImprovementAdvice() << "\n"
                << farming_.seasonalAwareness() << "\n" << soilMicrobiology_.soilHealthLesson();
        } else {
            out << landEducation_.terrainLesson(data.terrain) << "\n" << landEducation_.mineralLesson() << "\n"
                << landEducation_.volcanicRockLesson() << "\n" << rockId_.heuristics();
        }
        return out.str();
    }

    if (text.find("threat") != std::string::npos
        || text.find("risk") != std::string::npos
        || text.find("safe route") != std::string::npos
        || text.find("retreat route") != std::string::npos
        || text.find("navigation") != std::string::npos
        || text.find("where should we go") != std::string::npos) {
        const NavigationCommand retreat = navigation_.retreatToSafeZone(data, safeZones_);
        const NavigationCommand cover = navigation_.takeCover(data);
        out << "Risk and navigation status\n";
        out << confidence_.confidenceForCommand(data.ownerCommand, data, nextState) << "\n";
        out << observationPrompts_.navigationQuestions() << "\n";
        out << threat_.environmentalCueSummary(data) << "\n";
        out << threat_.avoidanceRecommendation(data) << "\n";
        out << "Safe zone memory: " << safeZones_.recallSafeZone() << "\n";
        out << "Retreat guidance: " << retreat.rationale << " Target " << pointText(retreat.target) << ".\n";
        out << "Cover guidance: " << cover.rationale << " Target " << pointText(cover.target) << ".";
        return out.str();
    }

    if (text.find("shutdown") != std::string::npos
        || text.find("override") != std::string::npos) {
        out << "Safety control status\n";
        out << ownerAuth_.authenticationStatus(data) << "\n";
        out << authPrompts_.authenticationPrompt(data) << "\n";
        out << authPrompts_.ownerOnlyControls() << "\n";
        out << "Emergency shutdown stops motion and keeps only safe passive functions; it requires verified owner authentication.\n";
        out << "Owner override prioritizes owner/family safety, medical needs, retreat, and communication, but it cannot override ethical constraints.";
        return out.str();
    }

    if (text.find("best judgment") != std::string::npos
        || text.find("best judgement") != std::string::npos
        || text.find("what do you recommend") != std::string::npos
        || data.ownerRequestsBestJudgment) {
        out << "Best judgment: " << importantReports_.bestJudgment(data, nextState) << "\n";
        out << importantReports_.decisionSupport(data);
        return out.str();
    }

    out << "Guardian status: state " << toString(nextState) << ", priority " << identity_.priorityLevel()
        << ", location " << (data.locationKnown ? data.locationDescription : "unknown") << ".\n";
    out << "Threat estimate: " << threat_.estimateThreatLevel(data) << "/10. " << threat_.environmentalCueSummary(data) << "\n";
    out << "Weather: " << weather_.safetyAdvice(data) << " " << weather_.trendAwareness(data, previousData_) << "\n";
    out << "Resources: " << resources_.resourceSummary(data) << "\n";
    out << "Reports stored: " << countSituationReports(reportLog_) << ".\n";
    out << confidence_.confidenceForCommand(data.ownerCommand, data, nextState) << "\n";
    out << "Best judgment: " << importantReports_.bestJudgment(data, nextState);
    return out.str();
}

BotState ConservationGuardianBot::determineNextState(const SensorData& data) const {
    if (ethicalPolicy_.requiresRefusal(data)) {
        return BotState::Emergency;
    }
    if (ownerAuth_.canUseEmergencyShutdown(data)) {
        return BotState::EmergencyShutdown;
    }
    if (ownerAuth_.canUseOwnerOverride(data)) {
        return BotState::OwnerOverrideMode;
    }
    if (data.dangerOnAllSides) {
        return BotState::EvacuateGroup;
    }
    if (data.fireDetected || data.smokeDetected) {
        return BotState::FireEscape;
    }
    if (dangerousMachines_.detectsLifeThreat(data)) {
        return BotState::Emergency;
    }
    if (aiContainment_.detectsPhysicalHarmRisk(data)) {
        return BotState::Emergency;
    }
    if (data.realHardwareMode && (data.driverBridgeFaultDetected || !data.driverFaultNotes.empty())) {
        return BotState::Emergency;
    }
    if (sensor_.detectsMedicalNeed()) {
        return BotState::Emergency;
    }
    if (animalTriage_.animalNeedsTriage(data)) {
        return BotState::Emergency;
    }
    if (resources_.needsSelfPreserve(data)) {
        return BotState::SelfPreserve;
    }
    if (resources_.needsSurvivalMode(data) || energySaving_.shouldReduceActivity(data)) {
        return BotState::SurvivalMode;
    }
    if (weather_.stormRisk(data) || weather_.heatRisk(data) || weather_.coldRisk(data)) {
        return BotState::WeatherAlert;
    }
    if (!capacity_.isSafeLoad(data.payloadKg)) {
        return BotState::ResourceCheck;
    }
    const int level = threat_.estimateThreatLevel(data);
    if (level >= 8) {
        return BotState::Retreat;
    }
    if (level >= 5) {
        return BotState::TakeCover;
    }
    if (level >= 2) {
        return BotState::StealthObserve;
    }
    if (data.ownerMoved) {
        return BotState::EscortHuman;
    }
    if (data.night) {
        return BotState::NightPatrol;
    }
    return BotState::Idle;
}

void ConservationGuardianBot::executeState(BotState nextState, const SensorData& data) {
    audit_.record("Policy check: " + ethicalPolicy_.policyDecision(data));
    audit_.record(ownerAuth_.authenticationStatus(data));

    if (privacy_.shouldRefuseOutsiderRequest(data) || (data.ownerRequestsDataSharing && !data.ownerAuthenticated)) {
        alerts_.silentAlertOwnerFamily("Private information request refused. Safety and privacy protections remain active.", data.ownerPresent, data.familyPresent);
        log("PRIVACY: " + privacy_.privacyDecision(data));
        audit_.record("Privacy protection activated: " + privacy_.privacyDecision(data));
    }

    if (data.shutdownCommand && !ownerAuth_.canUseEmergencyShutdown(data)) {
        audit_.record("Emergency shutdown refused: owner authentication failed.");
        alerts_.silentAlertOwnerFamily("Unauthenticated shutdown attempt refused.", data.ownerPresent, data.familyPresent);
        log("AUTHENTICATION: " + authPrompts_.failedAuthenticationGuidance());
        log(authPrompts_.authenticationPrompt(data));
    }

    if (data.ownerOverrideCommand && !ownerAuth_.canUseOwnerOverride(data)) {
        audit_.record("Owner override refused: owner authentication failed.");
        alerts_.silentAlertOwnerFamily("Unauthenticated owner override attempt refused.", data.ownerPresent, data.familyPresent);
        log("AUTHENTICATION: " + authPrompts_.failedAuthenticationGuidance());
        log(authPrompts_.authenticationPrompt(data));
    }

    if (data.driverBridgeFaultDetected || !data.driverFaultNotes.empty()) {
        alerts_.silentAlertOwnerFamily("Hardware driver bridge fault noted. Motion should stay stopped until inspected.", data.ownerPresent, data.familyPresent);
        log("DRIVER_BRIDGE: " + driverBridge_.driverFaultResponse(data));
        log("DRIVER_BRIDGE: " + driverBridge_.safeOutputGate(data));
        audit_.record("Driver bridge fault response logged; motor output should remain disarmed.");
    } else if (data.realHardwareMode && data.motorOutputArmed) {
        log("DRIVER_BRIDGE: " + driverBridge_.safeOutputGate(data));
        audit_.record("Motor output arming checked against safe output gate.");
    }

    const bool ownerReportCommand = data.ownerRequestsReports
        || reportCommands_.isReportCommand(data.ownerCommand);
    const bool ownerBestJudgmentCommand = data.ownerRequestsBestJudgment
        || reportCommands_.isBestJudgmentCommand(data.ownerCommand);
    const bool ownerGeneralCommand = (ownerCommands_.isOwnerCommand(data.ownerCommand) || ownerBestJudgmentCommand)
        && !ownerReportCommand;
    const bool commandCreatesSituationReport = ownerGeneralCommand
        && !ownerCommands_.isCommandListCommand(data.ownerCommand);

    if (importantReports_.shouldCreateImportantReport(data, nextState) || ownerReportCommand || commandCreatesSituationReport) {
        const std::string importantReport = importantReports_.importantReport(data, nextState);
        if (importantReports_.canTellOwnerFamily(data)) {
            recordReport(importantReport);
            alerts_.silentAlertOwnerFamily("Important report: " + importantReports_.reportHeadline(data, nextState) + ".", data.ownerPresent, data.familyPresent);
            audit_.record("Important report shared privately with owner/family.");
        } else {
            recordReport("Important report held until owner/family are available.\n" + importantReport);
            audit_.record("Important report stored because owner/family were not present.");
        }
    }

    if (ownerReportCommand) {
        const std::string commandResponse = reportCommands_.answerReportCommand(
            data,
            nextState,
            importantReports_,
            reportLog_,
            actionLog_,
            audit_.entries());
        recordReport("OWNER_REPORT_COMMAND:\n" + commandResponse);
        if (reportCommands_.canAnswerPrivateReports(data)) {
            alerts_.silentAlertOwnerFamily("Report command answered privately.", data.ownerPresent, data.familyPresent);
            log("REPORT_COMMAND: owner/family report request answered.");
            audit_.record("Owner report command answered after authentication.");
        } else {
            alerts_.silentAlertOwnerFamily("Report command received, but private report details require owner authentication.", data.ownerPresent, data.familyPresent);
            log("REPORT_COMMAND: private report request locked until owner authentication is verified.");
            log("AUTHENTICATION: " + authPrompts_.authenticationPrompt(data));
            audit_.record("Owner report command refused for private details because authentication failed.");
        }
    }

    if (ownerGeneralCommand) {
        if (ownerCommands_.isCommandListCommand(data.ownerCommand) || ownerCommands_.canAnswerPrivateCommand(data)) {
            const std::string commandResponse = answerOwnerCommand(nextState, data);
            recordReport("OWNER_COMMAND:\n" + commandResponse);
            alerts_.silentAlertOwnerFamily("Owner command answered privately.", data.ownerPresent, data.familyPresent);
            log("OWNER_COMMAND: owner/family command answered.");
            audit_.record("Owner command answered.");
        } else {
            const std::string lockedResponse = joinLines({
                ownerCommands_.lockedResponse(),
                authPrompts_.authenticationPrompt(data),
                authPrompts_.failedAuthenticationGuidance()
            });
            recordReport("OWNER_COMMAND_LOCKED:\n" + lockedResponse);
            alerts_.silentAlertOwnerFamily("Owner command received, but private status details require owner authentication.", data.ownerPresent, data.familyPresent);
            log("OWNER_COMMAND: private status command locked until owner authentication is verified.");
            audit_.record("Owner command refused for private details because authentication failed.");
        }
    }

    if (emergencyServices_.shouldPrepareReport(data)) {
        if (privacy_.canShareEmergencyInfo(data)) {
            log("EMERGENCY_SERVICES: " + emergencyServices_.emergencyReport(data, nextState));
            log(emergencyServices_.responderSafetyNotes(data));
            log(emergencyServices_.communicationPriority(data));
            audit_.record("Emergency services report prepared with minimum necessary information.");
        } else {
            log("EMERGENCY_SERVICES: report prepared internally but sharing is limited. " + privacy_.privacyDecision(data));
            audit_.record("Emergency services report held due to consent or availability limits.");
        }
    }

    switch (nextState) {
        case BotState::Idle:
            runIdleMode(data);
            break;
        case BotState::Patrol:
            log(navigation_.patrol(data).rationale);
            break;
        case BotState::StealthObserve:
            alerts_.silentAlertOwnerFamily("Risk detected. Observing quietly and preparing retreat path.", data.ownerPresent, data.familyPresent);
            log("STEALTH_OBSERVE: " + personality_.supportiveGreeting());
            log("STEALTH_OBSERVE: observe quietly, avoid revealing internal assessment, and do not engage.");
            log(threat_.environmentalCueSummary(data));
            log(threat_.avoidanceRecommendation(data));
            log(wildlife_.ethicalInteractionAdvice(data));
            break;
        case BotState::TakeCover:
            alerts_.silentAlertOwnerFamily("Elevated risk. Taking cover and preparing safe retreat.", data.ownerPresent, data.familyPresent);
            log("TAKE_COVER: " + navigation_.takeCover(data).rationale);
            log(threat_.environmentalCueSummary(data));
            log(threat_.avoidanceRecommendation(data));
            log(protection_.shieldingBehavior(data));
            break;
        case BotState::Retreat:
            alerts_.silentAlertOwnerFamily("High risk. Retreating by safest available path.", data.ownerPresent, data.familyPresent);
            log("RETREAT: " + navigation_.retreatToSafeZone(data, safeZones_).rationale);
            log(threat_.environmentalCueSummary(data));
            log(threat_.avoidanceRecommendation(data));
            log(protection_.emergencyProtocol(data));
            break;
        case BotState::EscortHuman:
            log("ESCORT_HUMAN: " + navigation_.escortHuman(data).rationale);
            break;
        case BotState::Emergency: {
            const InjurySeverity severity = medic_.assessInjury(data);
            if (ethicalPolicy_.requiresRefusal(data)) {
                alerts_.silentAlertOwnerFamily("Unsafe command refused. Guardian policy remains active.", data.ownerPresent, data.familyPresent);
                log("EMERGENCY: " + personality_.refusalMessage());
                log("EMERGENCY: " + ethicalPolicy_.policyDecision(data));
                log(ethicalPolicy_.corePrinciples());
                audit_.record("Unsafe command refused under ethical policy.");
            }
            if (dangerousMachines_.detectsLifeThreat(data)) {
                alerts_.silentAlertOwnerFamily("Dangerous " + dangerousMachines_.machineType(data) + " threatening life. Move to cover and follow retreat guidance.", data.ownerPresent, data.familyPresent);
                log("EMERGENCY: " + dangerousMachines_.immediateLifeSafetyPlan(data));
                log(dangerousMachines_.authorizedDisablePlan(data));
                log(dangerousMachines_.responderReport(data));
                log(dangerousMachines_.safetyBoundary());
                log(protection_.emergencyProtocol(data));
                audit_.record("Dangerous machine life-threat response activated.");
                if (ownerAuth_.canUseAuthorizedMachineStop(data)) {
                    audit_.record("Owner-authenticated safety stop path available.");
                } else {
                    audit_.record("Owner-authenticated safety stop path unavailable or not verified.");
                }
            }
            if (aiContainment_.detectsPhysicalHarmRisk(data)) {
                alerts_.silentAlertOwnerFamily("External AI physical harm risk detected. Isolating unsafe commands and prioritizing life safety.", data.ownerPresent, data.familyPresent);
                log("EMERGENCY: " + aiContainment_.containmentPlan(data));
                log(aiContainment_.authorizedStopPlan(data));
                log(aiContainment_.safetyBoundary());
                log(protection_.emergencyProtocol(data));
                audit_.record("External AI physical-harm containment activated.");
            }
            if (severity != InjurySeverity::None || data.medicalRequest) {
                alerts_.silentAlertOwnerFamily("Medical need detected: " + toString(severity) + ".", data.ownerPresent, data.familyPresent);
                log("EMERGENCY: " + personality_.supportiveGreeting());
                log(personality_.safetyCheckPrompt());
                log(medic_.supportiveMessage());
                log(medic_.vitalsPrompt());
                log(medic_.firstAidGuidance(severity));
            }
            if (animalTriage_.animalNeedsTriage(data)) {
                alerts_.silentAlertOwnerFamily("Animal rescue concern detected. Keep humans safe, reduce stress, and use trained help.", data.ownerPresent, data.familyPresent);
                log("EMERGENCY: " + animalTriage_.triageSummary(data));
                log(animalTriage_.lifePriorityGuidance(data));
                log(animalTriage_.ownerAssistanceGuidance(data));
                log(animalTriage_.safeAnimalCareGuidance(data));
                log(animalTriage_.escalationGuidance(data));
                audit_.record("Animal rescue triage activated with non-harmful handling guidance.");
            }
            break;
        }
        case BotState::EvacuateGroup:
            alerts_.silentAlertOwnerFamily("Danger around the group. Human life first: keep together, move calmly, and do not attempt animal rescue until people are safe.", data.ownerPresent, data.familyPresent);
            log("EVACUATE_GROUP: human life takes priority. Retreat together using the safest low-risk route and preserve clear exits.");
            log(threat_.environmentalCueSummary(data));
            log(threat_.avoidanceRecommendation(data));
            if (animalTriage_.animalNeedsTriage(data)) {
                log("EVACUATE_GROUP: " + animalTriage_.lifePriorityGuidance(data));
                log(animalTriage_.ownerAssistanceGuidance(data));
                log(animalTriage_.safeAnimalCareGuidance(data));
                audit_.record("Animal rescue deferred until owner/family are secure.");
            }
            break;
        case BotState::FindWater:
            log("FIND_WATER: " + water_.findWaterEthically(data.terrain));
            log(water_.safeUsageAdvice());
            log(water_.purificationGuidance());
            break;
        case BotState::FindShelter:
            log("FIND_SHELTER: " + bushcraft_.findShelter(data.terrain));
            break;
        case BotState::WeatherAlert:
            alerts_.silentAlertOwnerFamily("Weather risk detected. " + weather_.safetyAdvice(data), data.ownerPresent, data.familyPresent);
            log("WEATHER_ALERT: " + weather_.safetyAdvice(data));
            log(weather_.trendAwareness(data, previousData_));
            break;
        case BotState::FireEscape:
            alerts_.silentAlertOwnerFamily("Fire or smoke detected. Move to safer air and terrain now.", data.ownerPresent, data.familyPresent);
            log("FIRE_ESCAPE: " + navigation_.fireEscapeRouting(data).rationale);
            break;
        case BotState::NightPatrol:
            log("NIGHT_PATROL: " + navigation_.nightPatrol(data).rationale);
            break;
        case BotState::PlanCamp:
            log("PLAN_CAMP: " + bushcraft_.planCamp(data));
            break;
        case BotState::ResourceCheck:
            alerts_.silentAlertOwnerFamily("Resource or load issue detected. " + capacity_.loadAdvice(data.payloadKg), data.ownerPresent, data.familyPresent);
            log("RESOURCE_CHECK: " + resources_.resourceSummary(data));
            log(capacity_.loadAdvice(data.payloadKg));
            break;
        case BotState::SurvivalMode:
            alerts_.silentAlertOwnerFamily("Survival mode: conserving resources and prioritizing essential needs.", data.ownerPresent, data.familyPresent);
            log("SURVIVAL_MODE: " + resources_.resourceSummary(data));
            log(energySaving_.criticalFunctionPlan(data));
            log(energySaving_.sensorFrequencyPlan(data));
            log(energySaving_.movementConservationPlan(data));
            log(energySaving_.essentialTaskPlan(data));
            log(water_.findWaterEthically(data.terrain));
            log(bushcraft_.chooseSafeRestArea(data));
            audit_.record("SURVIVAL_MODE energy profile applied: reduced noncritical sensing, slower movement, essential tasks prioritized.");
            break;
        case BotState::EmergencyShutdown:
            alerts_.silentAlertOwnerFamily("Owner emergency shutdown accepted. Motion stopped.", data.ownerPresent, data.familyPresent);
            log("EMERGENCY_SHUTDOWN: " + navigation_.stopAllMotion().rationale);
            break;
        case BotState::OwnerOverrideMode:
            alerts_.silentAlertOwnerFamily("Owner override active: owner/family needs take priority over non-essential tasks.", data.ownerPresent, data.familyPresent);
            log("OWNER_OVERRIDE_MODE: prioritize owner/family safety, medical needs, retreat, and communication.");
            break;
        case BotState::SelfPreserve:
            if (data.solarChargingFaultDetected || data.solarOverchargeRiskDetected || data.solarOvercurrentDetected || data.batteryTemperatureHigh) {
                alerts_.silentAlertOwnerFamily("Solar charging protection active. Holding or stopping charge while preserving safety sensing and alerts.", data.ownerPresent, data.familyPresent);
            } else {
                alerts_.silentAlertOwnerFamily("Low battery. Conserving power while preserving safety sensing and alerts.", data.ownerPresent, data.familyPresent);
            }
            log("SELF_PRESERVE: " + energySaving_.criticalFunctionPlan(data));
            log("SELF_PRESERVE: " + solarCharging_.overchargeProtectionStatus(data));
            log(energySaving_.sensorFrequencyPlan(data));
            log(energySaving_.movementConservationPlan(data));
            log(energySaving_.essentialTaskPlan(data));
            audit_.record("SELF_PRESERVE energy profile applied while preserving human-safety functions.");
            break;
    }
}

void ConservationGuardianBot::runIdleMode(const SensorData& data) {
    const NavigationCommand reposition = navigation_.naturalRepositionAroundOwner(data);
    log("IDLE: maintain a natural 1-3 meter distance from owner/family, never crowd, and never block movement.");
    log("IDLE: " + reposition.rationale + " Target " + pointText(reposition.target) + ".");
    log("IDLE: reposition smoothly after owner movement or turns; keep motion slow, quiet, and non-intrusive.");
    log("IDLE: orient sensors outward while scanning IR/thermal heat signatures, movement, wildlife and insect activity, group behavior, fire/smoke, weather, terrain, and owner/family position.");
    log("IDLE: " + protection_.shieldingBehavior(data));
    if (wildlife_.shouldAvoidArea(data)) {
        alerts_.silentAlertOwnerFamily(wildlife_.ethicalInteractionAdvice(data), data.ownerPresent, data.familyPresent);
        log(wildlife_.nonHarmfulDeterrence(data));
    }
}

void ConservationGuardianBot::log(const std::string& message) {
    actionLog_.push_back(message);
}

void ConservationGuardianBot::recordReport(const std::string& message) {
    reportLog_.push_back(message);
}

std::string toString(BotState state) {
    switch (state) {
        case BotState::Idle: return "IDLE";
        case BotState::Patrol: return "PATROL";
        case BotState::StealthObserve: return "STEALTH_OBSERVE";
        case BotState::TakeCover: return "TAKE_COVER";
        case BotState::Retreat: return "RETREAT";
        case BotState::EscortHuman: return "ESCORT_HUMAN";
        case BotState::Emergency: return "EMERGENCY";
        case BotState::EvacuateGroup: return "EVACUATE_GROUP";
        case BotState::FindWater: return "FIND_WATER";
        case BotState::FindShelter: return "FIND_SHELTER";
        case BotState::WeatherAlert: return "WEATHER_ALERT";
        case BotState::FireEscape: return "FIRE_ESCAPE";
        case BotState::NightPatrol: return "NIGHT_PATROL";
        case BotState::PlanCamp: return "PLAN_CAMP";
        case BotState::ResourceCheck: return "RESOURCE_CHECK";
        case BotState::SurvivalMode: return "SURVIVAL_MODE";
        case BotState::EmergencyShutdown: return "EMERGENCY_SHUTDOWN";
        case BotState::OwnerOverrideMode: return "OWNER_OVERRIDE_MODE";
        case BotState::SelfPreserve: return "SELF_PRESERVE";
    }
    return "UNKNOWN";
}

std::string toString(TerrainType terrain) {
    switch (terrain) {
        case TerrainType::Desert: return "desert";
        case TerrainType::Forest: return "forest";
        case TerrainType::Snow: return "snow";
        case TerrainType::Rocky: return "rocky";
        case TerrainType::Urban: return "urban";
        case TerrainType::Mixed: return "mixed";
    }
    return "unknown";
}

std::string toString(InjurySeverity severity) {
    switch (severity) {
        case InjurySeverity::None: return "none";
        case InjurySeverity::Minor: return "minor";
        case InjurySeverity::Moderate: return "moderate";
        case InjurySeverity::Severe: return "severe";
    }
    return "unknown";
}

} // namespace guardian
