-- CreateTable
CREATE TABLE "City" (
    "id" SERIAL NOT NULL,
    "name" VARCHAR(255) NOT NULL,
    "inseeCode" VARCHAR(5) NOT NULL,
    "postalCode" VARCHAR(10),
    "departmentName" VARCHAR(255),
    "departmentCode" VARCHAR(2),
    "regionName" VARCHAR(255),
    "latitude" DECIMAL(10,8),
    "longitude" DECIMAL(11,8),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "City_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Agency" (
    "id" SERIAL NOT NULL,
    "name" VARCHAR(255) NOT NULL,
    "email" VARCHAR(255) NOT NULL,
    "phone" VARCHAR(20),
    "address" VARCHAR(255),
    "postalCode" VARCHAR(10),
    "subscriptionPlan" VARCHAR(50) NOT NULL DEFAULT 'free',
    "subscriptionStatus" VARCHAR(50) NOT NULL DEFAULT 'active',
    "subscriptionStartDate" TIMESTAMP(3),
    "subscriptionEndDate" TIMESTAMP(3),
    "status" VARCHAR(50) NOT NULL DEFAULT 'active',
    "logoUrl" VARCHAR(500),
    "website" VARCHAR(255),
    "siren" VARCHAR(14),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "cityId" INTEGER NOT NULL,

    CONSTRAINT "Agency_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AgencyCity" (
    "id" SERIAL NOT NULL,
    "priority" VARCHAR(50) NOT NULL DEFAULT 'primary',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "agencyId" INTEGER NOT NULL,
    "cityId" INTEGER NOT NULL,

    CONSTRAINT "AgencyCity_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "User" (
    "id" SERIAL NOT NULL,
    "firstName" VARCHAR(100) NOT NULL,
    "lastName" VARCHAR(100) NOT NULL,
    "email" VARCHAR(255) NOT NULL,
    "phone" VARCHAR(20),
    "passwordHash" VARCHAR(500),
    "authProvider" VARCHAR(50) NOT NULL DEFAULT 'email',
    "authProviderId" VARCHAR(255),
    "role" VARCHAR(50) NOT NULL,
    "assignedCities" JSONB,
    "status" VARCHAR(50) NOT NULL DEFAULT 'active',
    "lastLogin" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "agencyId" INTEGER NOT NULL,

    CONSTRAINT "User_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Property" (
    "id" SERIAL NOT NULL,
    "reference" VARCHAR(100) NOT NULL,
    "title" VARCHAR(255) NOT NULL,
    "transactionType" VARCHAR(50) NOT NULL,
    "propertyType" VARCHAR(50) NOT NULL,
    "address" VARCHAR(255) NOT NULL,
    "postalCode" VARCHAR(10),
    "latitude" DECIMAL(10,8),
    "longitude" DECIMAL(11,8),
    "price" DECIMAL(15,2) NOT NULL,
    "surface" INTEGER,
    "rooms" INTEGER,
    "bedrooms" INTEGER,
    "bathrooms" INTEGER,
    "floor" INTEGER,
    "hasElevator" BOOLEAN NOT NULL DEFAULT false,
    "hasBalcony" BOOLEAN NOT NULL DEFAULT false,
    "hasTerrrace" BOOLEAN NOT NULL DEFAULT false,
    "hasGarden" BOOLEAN NOT NULL DEFAULT false,
    "hasParking" BOOLEAN NOT NULL DEFAULT false,
    "hasCellar" BOOLEAN NOT NULL DEFAULT false,
    "isFurnished" BOOLEAN NOT NULL DEFAULT false,
    "availabilityDate" TIMESTAMP(3),
    "status" VARCHAR(50) NOT NULL DEFAULT 'available',
    "description" TEXT,
    "mainPhotoUrl" VARCHAR(500),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "agencyId" INTEGER NOT NULL,
    "assignedAgentId" INTEGER,
    "cityId" INTEGER NOT NULL,

    CONSTRAINT "Property_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Lead" (
    "id" SERIAL NOT NULL,
    "firstName" VARCHAR(100) NOT NULL,
    "lastName" VARCHAR(100) NOT NULL,
    "email" VARCHAR(255),
    "phone" VARCHAR(20),
    "source" VARCHAR(50) NOT NULL,
    "sourceMetadata" JSONB,
    "transactionType" VARCHAR(50) NOT NULL,
    "propertyType" VARCHAR(50) NOT NULL,
    "budgetMin" DECIMAL(15,2),
    "budgetMax" DECIMAL(15,2) NOT NULL,
    "surfaceMin" INTEGER,
    "surfaceMax" INTEGER,
    "roomsMin" INTEGER,
    "roomsMax" INTEGER,
    "bedroomsMin" INTEGER,
    "bedroomsMax" INTEGER,
    "availabilityDate" TIMESTAMP(3),
    "furnishedRequired" BOOLEAN NOT NULL DEFAULT false,
    "notes" TEXT,
    "status" VARCHAR(50) NOT NULL DEFAULT 'new',
    "priority" VARCHAR(50) NOT NULL DEFAULT 'normal',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "firstContactAt" TIMESTAMP(3),
    "agencyId" INTEGER NOT NULL,
    "assignedAgentId" INTEGER,

    CONSTRAINT "Lead_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "LeadCity" (
    "id" SERIAL NOT NULL,
    "priority" VARCHAR(50) NOT NULL DEFAULT 'preferred',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "leadId" INTEGER NOT NULL,
    "cityId" INTEGER NOT NULL,

    CONSTRAINT "LeadCity_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "LeadPreference" (
    "id" SERIAL NOT NULL,
    "criteriaKey" VARCHAR(100) NOT NULL,
    "valueType" VARCHAR(50) NOT NULL,
    "value" TEXT NOT NULL,
    "importance" VARCHAR(50) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "leadId" INTEGER NOT NULL,

    CONSTRAINT "LeadPreference_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Match" (
    "id" SERIAL NOT NULL,
    "score" DECIMAL(5,2) NOT NULL,
    "eligible" BOOLEAN NOT NULL,
    "matchDetails" JSONB NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "agencyId" INTEGER NOT NULL,
    "leadId" INTEGER NOT NULL,
    "propertyId" INTEGER NOT NULL,

    CONSTRAINT "Match_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "LeadActivity" (
    "id" SERIAL NOT NULL,
    "actionType" VARCHAR(100) NOT NULL,
    "description" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "agencyId" INTEGER NOT NULL,
    "leadId" INTEGER NOT NULL,
    "userId" INTEGER,

    CONSTRAINT "LeadActivity_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "DailyAgencyStat" (
    "id" SERIAL NOT NULL,
    "date" DATE NOT NULL,
    "leadsCreated" INTEGER NOT NULL DEFAULT 0,
    "leadsContacted" INTEGER NOT NULL DEFAULT 0,
    "leadsQualified" INTEGER NOT NULL DEFAULT 0,
    "leadsVisitsScheduled" INTEGER NOT NULL DEFAULT 0,
    "leadsWon" INTEGER NOT NULL DEFAULT 0,
    "propertiesCreated" INTEGER NOT NULL DEFAULT 0,
    "propertiesSold" INTEGER NOT NULL DEFAULT 0,
    "propertiesRented" INTEGER NOT NULL DEFAULT 0,
    "totalMatches" INTEGER NOT NULL DEFAULT 0,
    "avgMatchScore" DECIMAL(5,2),
    "avgResponseTimeMinutes" INTEGER,
    "agencyId" INTEGER NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "DailyAgencyStat_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "IntegrationConfig" (
    "id" SERIAL NOT NULL,
    "source" VARCHAR(50) NOT NULL,
    "apiKey" VARCHAR(500) NOT NULL,
    "status" VARCHAR(50) NOT NULL DEFAULT 'pending',
    "errorMessage" TEXT,
    "lastCheckAt" TIMESTAMP(3),
    "lastSyncAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "agencyId" INTEGER NOT NULL,

    CONSTRAINT "IntegrationConfig_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "IntegrationLog" (
    "id" SERIAL NOT NULL,
    "source" VARCHAR(50) NOT NULL,
    "sourceId" VARCHAR(255) NOT NULL,
    "status" VARCHAR(50) NOT NULL,
    "errorMessage" TEXT,
    "leadId" INTEGER,
    "data" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "agencyId" INTEGER NOT NULL,

    CONSTRAINT "IntegrationLog_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "City_inseeCode_key" ON "City"("inseeCode");

-- CreateIndex
CREATE INDEX "City_name_idx" ON "City"("name");

-- CreateIndex
CREATE INDEX "City_inseeCode_idx" ON "City"("inseeCode");

-- CreateIndex
CREATE INDEX "City_postalCode_idx" ON "City"("postalCode");

-- CreateIndex
CREATE INDEX "City_departmentCode_idx" ON "City"("departmentCode");

-- CreateIndex
CREATE UNIQUE INDEX "Agency_email_key" ON "Agency"("email");

-- CreateIndex
CREATE INDEX "Agency_status_idx" ON "Agency"("status");

-- CreateIndex
CREATE INDEX "Agency_email_idx" ON "Agency"("email");

-- CreateIndex
CREATE INDEX "AgencyCity_agencyId_idx" ON "AgencyCity"("agencyId");

-- CreateIndex
CREATE INDEX "AgencyCity_cityId_idx" ON "AgencyCity"("cityId");

-- CreateIndex
CREATE UNIQUE INDEX "AgencyCity_agencyId_cityId_key" ON "AgencyCity"("agencyId", "cityId");

-- CreateIndex
CREATE UNIQUE INDEX "User_email_key" ON "User"("email");

-- CreateIndex
CREATE INDEX "User_agencyId_idx" ON "User"("agencyId");

-- CreateIndex
CREATE INDEX "User_email_idx" ON "User"("email");

-- CreateIndex
CREATE INDEX "User_role_idx" ON "User"("role");

-- CreateIndex
CREATE INDEX "User_status_idx" ON "User"("status");

-- CreateIndex
CREATE INDEX "Property_agencyId_idx" ON "Property"("agencyId");

-- CreateIndex
CREATE INDEX "Property_assignedAgentId_idx" ON "Property"("assignedAgentId");

-- CreateIndex
CREATE INDEX "Property_cityId_idx" ON "Property"("cityId");

-- CreateIndex
CREATE INDEX "Property_status_idx" ON "Property"("status");

-- CreateIndex
CREATE INDEX "Property_transactionType_idx" ON "Property"("transactionType");

-- CreateIndex
CREATE INDEX "Property_propertyType_idx" ON "Property"("propertyType");

-- CreateIndex
CREATE INDEX "Property_price_idx" ON "Property"("price");

-- CreateIndex
CREATE INDEX "Property_surface_idx" ON "Property"("surface");

-- CreateIndex
CREATE INDEX "Property_bedrooms_idx" ON "Property"("bedrooms");

-- CreateIndex
CREATE UNIQUE INDEX "Property_agencyId_reference_key" ON "Property"("agencyId", "reference");

-- CreateIndex
CREATE INDEX "Lead_agencyId_idx" ON "Lead"("agencyId");

-- CreateIndex
CREATE INDEX "Lead_assignedAgentId_idx" ON "Lead"("assignedAgentId");

-- CreateIndex
CREATE INDEX "Lead_status_idx" ON "Lead"("status");

-- CreateIndex
CREATE INDEX "Lead_createdAt_idx" ON "Lead"("createdAt");

-- CreateIndex
CREATE INDEX "Lead_priority_idx" ON "Lead"("priority");

-- CreateIndex
CREATE INDEX "Lead_source_idx" ON "Lead"("source");

-- CreateIndex
CREATE INDEX "Lead_transactionType_idx" ON "Lead"("transactionType");

-- CreateIndex
CREATE INDEX "LeadCity_leadId_idx" ON "LeadCity"("leadId");

-- CreateIndex
CREATE INDEX "LeadCity_cityId_idx" ON "LeadCity"("cityId");

-- CreateIndex
CREATE UNIQUE INDEX "LeadCity_leadId_cityId_key" ON "LeadCity"("leadId", "cityId");

-- CreateIndex
CREATE INDEX "LeadPreference_leadId_idx" ON "LeadPreference"("leadId");

-- CreateIndex
CREATE INDEX "LeadPreference_criteriaKey_idx" ON "LeadPreference"("criteriaKey");

-- CreateIndex
CREATE INDEX "Match_agencyId_idx" ON "Match"("agencyId");

-- CreateIndex
CREATE INDEX "Match_leadId_idx" ON "Match"("leadId");

-- CreateIndex
CREATE INDEX "Match_propertyId_idx" ON "Match"("propertyId");

-- CreateIndex
CREATE INDEX "Match_score_idx" ON "Match"("score");

-- CreateIndex
CREATE INDEX "Match_eligible_idx" ON "Match"("eligible");

-- CreateIndex
CREATE UNIQUE INDEX "Match_leadId_propertyId_key" ON "Match"("leadId", "propertyId");

-- CreateIndex
CREATE INDEX "LeadActivity_leadId_idx" ON "LeadActivity"("leadId");

-- CreateIndex
CREATE INDEX "LeadActivity_userId_idx" ON "LeadActivity"("userId");

-- CreateIndex
CREATE INDEX "LeadActivity_agencyId_idx" ON "LeadActivity"("agencyId");

-- CreateIndex
CREATE INDEX "DailyAgencyStat_agencyId_idx" ON "DailyAgencyStat"("agencyId");

-- CreateIndex
CREATE UNIQUE INDEX "DailyAgencyStat_agencyId_date_key" ON "DailyAgencyStat"("agencyId", "date");

-- CreateIndex
CREATE INDEX "IntegrationConfig_agencyId_idx" ON "IntegrationConfig"("agencyId");

-- CreateIndex
CREATE INDEX "IntegrationConfig_status_idx" ON "IntegrationConfig"("status");

-- CreateIndex
CREATE UNIQUE INDEX "IntegrationConfig_agencyId_source_key" ON "IntegrationConfig"("agencyId", "source");

-- CreateIndex
CREATE INDEX "IntegrationLog_agencyId_idx" ON "IntegrationLog"("agencyId");

-- CreateIndex
CREATE INDEX "IntegrationLog_source_idx" ON "IntegrationLog"("source");

-- CreateIndex
CREATE INDEX "IntegrationLog_status_idx" ON "IntegrationLog"("status");

-- CreateIndex
CREATE INDEX "IntegrationLog_createdAt_idx" ON "IntegrationLog"("createdAt");

-- AddForeignKey
ALTER TABLE "Agency" ADD CONSTRAINT "Agency_cityId_fkey" FOREIGN KEY ("cityId") REFERENCES "City"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AgencyCity" ADD CONSTRAINT "AgencyCity_agencyId_fkey" FOREIGN KEY ("agencyId") REFERENCES "Agency"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AgencyCity" ADD CONSTRAINT "AgencyCity_cityId_fkey" FOREIGN KEY ("cityId") REFERENCES "City"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "User" ADD CONSTRAINT "User_agencyId_fkey" FOREIGN KEY ("agencyId") REFERENCES "Agency"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Property" ADD CONSTRAINT "Property_agencyId_fkey" FOREIGN KEY ("agencyId") REFERENCES "Agency"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Property" ADD CONSTRAINT "Property_assignedAgentId_fkey" FOREIGN KEY ("assignedAgentId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Property" ADD CONSTRAINT "Property_cityId_fkey" FOREIGN KEY ("cityId") REFERENCES "City"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Lead" ADD CONSTRAINT "Lead_agencyId_fkey" FOREIGN KEY ("agencyId") REFERENCES "Agency"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Lead" ADD CONSTRAINT "Lead_assignedAgentId_fkey" FOREIGN KEY ("assignedAgentId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "LeadCity" ADD CONSTRAINT "LeadCity_leadId_fkey" FOREIGN KEY ("leadId") REFERENCES "Lead"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "LeadCity" ADD CONSTRAINT "LeadCity_cityId_fkey" FOREIGN KEY ("cityId") REFERENCES "City"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "LeadPreference" ADD CONSTRAINT "LeadPreference_leadId_fkey" FOREIGN KEY ("leadId") REFERENCES "Lead"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Match" ADD CONSTRAINT "Match_agencyId_fkey" FOREIGN KEY ("agencyId") REFERENCES "Agency"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Match" ADD CONSTRAINT "Match_leadId_fkey" FOREIGN KEY ("leadId") REFERENCES "Lead"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Match" ADD CONSTRAINT "Match_propertyId_fkey" FOREIGN KEY ("propertyId") REFERENCES "Property"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "LeadActivity" ADD CONSTRAINT "LeadActivity_agencyId_fkey" FOREIGN KEY ("agencyId") REFERENCES "Agency"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "LeadActivity" ADD CONSTRAINT "LeadActivity_leadId_fkey" FOREIGN KEY ("leadId") REFERENCES "Lead"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "LeadActivity" ADD CONSTRAINT "LeadActivity_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DailyAgencyStat" ADD CONSTRAINT "DailyAgencyStat_agencyId_fkey" FOREIGN KEY ("agencyId") REFERENCES "Agency"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "IntegrationConfig" ADD CONSTRAINT "IntegrationConfig_agencyId_fkey" FOREIGN KEY ("agencyId") REFERENCES "Agency"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "IntegrationLog" ADD CONSTRAINT "IntegrationLog_leadId_fkey" FOREIGN KEY ("leadId") REFERENCES "Lead"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "IntegrationLog" ADD CONSTRAINT "IntegrationLog_agencyId_fkey" FOREIGN KEY ("agencyId") REFERENCES "Agency"("id") ON DELETE CASCADE ON UPDATE CASCADE;
