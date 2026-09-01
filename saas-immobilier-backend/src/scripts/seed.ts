/**
 * SEED SCRIPT
 * Peupler la base de données avec:
 * - Communes françaises (Marseille, Paris, Lyon, etc.)
 * - Agence de test
 * - Users de test
 * - Leads de test
 * - Properties de test
 */

import { PrismaClient } from "@prisma/client";
import bcrypt from "bcryptjs";

const prisma = new PrismaClient();

// Données de communes (subset pour la démo)
const CITIES = [
  // Marseille
  {
    name: "Marseille",
    inseeCode: "13055",
    postalCode: "13000",
    departmentName: "Bouches-du-Rhône",
    departmentCode: "13",
    regionName: "Provence-Alpes-Côte d'Azur",
    latitude: "43.2965",
    longitude: "5.3698",
  },
  {
    name: "Aubagne",
    inseeCode: "13005",
    postalCode: "13400",
    departmentName: "Bouches-du-Rhône",
    departmentCode: "13",
    regionName: "Provence-Alpes-Côte d'Azur",
    latitude: "43.2934",
    longitude: "5.5876",
  },
  {
    name: "Cassis",
    inseeCode: "13022",
    postalCode: "13260",
    departmentName: "Bouches-du-Rhône",
    departmentCode: "13",
    regionName: "Provence-Alpes-Côte d'Azur",
    latitude: "43.2158",
    longitude: "5.5368",
  },
  {
    name: "La Ciotat",
    inseeCode: "13033",
    postalCode: "13600",
    departmentName: "Bouches-du-Rhône",
    departmentCode: "13",
    regionName: "Provence-Alpes-Côte d'Azur",
    latitude: "43.1704",
    longitude: "5.6024",
  },

  // Paris
  {
    name: "Paris",
    inseeCode: "75056",
    postalCode: "75000",
    departmentName: "Paris",
    departmentCode: "75",
    regionName: "Île-de-France",
    latitude: "48.8566",
    longitude: "2.3522",
  },
  {
    name: "Boulogne-Billancourt",
    inseeCode: "92012",
    postalCode: "92100",
    departmentName: "Hauts-de-Seine",
    departmentCode: "92",
    regionName: "Île-de-France",
    latitude: "48.8355",
    longitude: "2.2399",
  },
  {
    name: "Neuilly-sur-Seine",
    inseeCode: "92051",
    postalCode: "92200",
    departmentName: "Hauts-de-Seine",
    departmentCode: "92",
    regionName: "Île-de-France",
    latitude: "48.8821",
    longitude: "2.2704",
  },

  // Lyon
  {
    name: "Lyon",
    inseeCode: "69123",
    postalCode: "69000",
    departmentName: "Rhône",
    departmentCode: "69",
    regionName: "Auvergne-Rhône-Alpes",
    latitude: "45.7640",
    longitude: "4.8357",
  },
  {
    name: "Villeurbanne",
    inseeCode: "69266",
    postalCode: "69100",
    departmentName: "Rhône",
    departmentCode: "69",
    regionName: "Auvergne-Rhône-Alpes",
    latitude: "45.7700",
    longitude: "4.8900",
  },
];

async function main() {
  console.log("🌱 Starting seed...\n");

  try {
    // 1. CRÉER LES COMMUNES
    console.log("📍 Creating cities...");
    const cities = await Promise.all(
      CITIES.map((city) =>
        prisma.city.upsert({
          where: { inseeCode: city.inseeCode },
          update: {},
          create: {
            name: city.name,
            inseeCode: city.inseeCode,
            postalCode: city.postalCode,
            departmentName: city.departmentName,
            departmentCode: city.departmentCode,
            regionName: city.regionName,
            latitude: parseFloat(city.latitude),
            longitude: parseFloat(city.longitude),
          },
        })
      )
    );
    console.log(`✅ Created ${cities.length} cities\n`);

    // 2. CRÉER LES AGENCES
    console.log("🏢 Creating agencies...");

    const agency1 = await prisma.agency.upsert({
      where: { email: "marseille@agencyimmo.com" },
      update: {},
      create: {
        name: "Marseille Immo",
        email: "marseille@agencyimmo.com",
        phone: "04 91 00 00 00",
        address: "123 Rue de la Canebière",
        postalCode: "13000",
        cityId: cities[0].id, // Marseille
        subscriptionPlan: "pro",
        subscriptionStatus: "active",
        status: "active",
        website: "www.marseille-immo.fr",
        siren: "12345678901234",
      },
    });

    const agency2 = await prisma.agency.upsert({
      where: { email: "paris@agencyimmo.com" },
      update: {},
      create: {
        name: "Paris Immo",
        email: "paris@agencyimmo.com",
        phone: "01 42 00 00 00",
        address: "456 Avenue des Champs-Élysées",
        postalCode: "75000",
        cityId: cities[4].id, // Paris
        subscriptionPlan: "pro",
        subscriptionStatus: "active",
        status: "active",
        website: "www.paris-immo.fr",
        siren: "98765432109876",
      },
    });

    console.log(`✅ Created 2 agencies\n`);

    // 3. ASSIGNER LES VILLES AUX AGENCES
    console.log("🗺️  Assigning cities to agencies...");

    // Marseille Immo -> Marseille, Aubagne, Cassis, La Ciotat
    await Promise.all([
      prisma.agencyCity.upsert({
        where: { agencyId_cityId: { agencyId: agency1.id, cityId: cities[0].id } },
        update: {},
        create: { agencyId: agency1.id, cityId: cities[0].id },
      }),
      prisma.agencyCity.upsert({
        where: { agencyId_cityId: { agencyId: agency1.id, cityId: cities[1].id } },
        update: {},
        create: { agencyId: agency1.id, cityId: cities[1].id },
      }),
      prisma.agencyCity.upsert({
        where: { agencyId_cityId: { agencyId: agency1.id, cityId: cities[2].id } },
        update: {},
        create: { agencyId: agency1.id, cityId: cities[2].id },
      }),
      prisma.agencyCity.upsert({
        where: { agencyId_cityId: { agencyId: agency1.id, cityId: cities[3].id } },
        update: {},
        create: { agencyId: agency1.id, cityId: cities[3].id },
      }),

      // Paris Immo -> Paris, Boulogne, Neuilly
      prisma.agencyCity.upsert({
        where: { agencyId_cityId: { agencyId: agency2.id, cityId: cities[4].id } },
        update: {},
        create: { agencyId: agency2.id, cityId: cities[4].id },
      }),
      prisma.agencyCity.upsert({
        where: { agencyId_cityId: { agencyId: agency2.id, cityId: cities[5].id } },
        update: {},
        create: { agencyId: agency2.id, cityId: cities[5].id },
      }),
      prisma.agencyCity.upsert({
        where: { agencyId_cityId: { agencyId: agency2.id, cityId: cities[6].id } },
        update: {},
        create: { agencyId: agency2.id, cityId: cities[6].id },
      }),
    ]);

    console.log(`✅ Assigned cities to agencies\n`);

    // 4. CRÉER LES UTILISATEURS
    console.log("👥 Creating users...");

    const hashedPassword = await bcrypt.hash("password123", 10);

    const agent1 = await prisma.user.upsert({
      where: { email: "jean.dupont@marseille-immo.fr" },
      update: {},
      create: {
        agencyId: agency1.id,
        firstName: "Jean",
        lastName: "Dupont",
        email: "jean.dupont@marseille-immo.fr",
        phone: "06 12 34 56 78",
        passwordHash: hashedPassword,
        role: "agent",
        status: "active",
        assignedCities: [cities[0].id, cities[1].id], // Marseille, Aubagne
      },
    });

    const admin1 = await prisma.user.upsert({
      where: { email: "admin@marseille-immo.fr" },
      update: {},
      create: {
        agencyId: agency1.id,
        firstName: "Admin",
        lastName: "Marseille",
        email: "admin@marseille-immo.fr",
        phone: "04 91 00 00 01",
        passwordHash: hashedPassword,
        role: "admin",
        status: "active",
      },
    });

    const agent2 = await prisma.user.upsert({
      where: { email: "sophie.martin@paris-immo.fr" },
      update: {},
      create: {
        agencyId: agency2.id,
        firstName: "Sophie",
        lastName: "Martin",
        email: "sophie.martin@paris-immo.fr",
        phone: "06 98 76 54 32",
        passwordHash: hashedPassword,
        role: "agent",
        status: "active",
        assignedCities: [cities[4].id, cities[5].id], // Paris, Boulogne
      },
    });

    console.log(`✅ Created 3 users\n`);

    // 5. CRÉER DES BIENS
    console.log("🏠 Creating properties...");

    const properties = await Promise.all([
      // Marseille properties
      prisma.property.upsert({
        where: {
          agencyId_reference: { agencyId: agency1.id, reference: "MAR-001" },
        },
        update: {},
        create: {
          agencyId: agency1.id,
          assignedAgentId: agent1.id,
          reference: "MAR-001",
          title: "T3 Marseille 8e - Lumineux",
          transactionType: "rent",
          propertyType: "apartment",
          cityId: cities[0].id, // Marseille
          address: "123 Rue de la Canebière",
          postalCode: "13008",
          price: parseFloat("1150"),
          surface: 65,
          rooms: 3,
          bedrooms: 2,
          bathrooms: 1,
          floor: 2,
          hasElevator: true,
          hasBalcony: false,
          hasParking: true,
          isFurnished: false,
          description: "Bel appartement lumineux avec vue",
          status: "available",
        },
      }),

      prisma.property.upsert({
        where: {
          agencyId_reference: { agencyId: agency1.id, reference: "MAR-002" },
        },
        update: {},
        create: {
          agencyId: agency1.id,
          assignedAgentId: agent1.id,
          reference: "MAR-002",
          title: "T4 Marseille 6e - Récent",
          transactionType: "rent",
          propertyType: "apartment",
          cityId: cities[0].id,
          address: "456 Avenue Victor Hugo",
          postalCode: "13006",
          price: parseFloat("1300"),
          surface: 85,
          rooms: 4,
          bedrooms: 3,
          bathrooms: 2,
          floor: 3,
          hasElevator: true,
          hasBalcony: true,
          hasParking: true,
          isFurnished: false,
          description: "Appartement neuf, très bien équipé",
          status: "available",
        },
      }),

      prisma.property.upsert({
        where: {
          agencyId_reference: { agencyId: agency1.id, reference: "AUB-001" },
        },
        update: {},
        create: {
          agencyId: agency1.id,
          assignedAgentId: agent1.id,
          reference: "AUB-001",
          title: "Maison Aubagne - Jardin",
          transactionType: "rent",
          propertyType: "house",
          cityId: cities[1].id, // Aubagne
          address: "789 Rue du Parc",
          postalCode: "13400",
          price: parseFloat("1100"),
          surface: 100,
          rooms: 4,
          bedrooms: 3,
          bathrooms: 2,
          hasGarden: true,
          hasParking: true,
          isFurnished: false,
          description: "Maison familiale avec jardin",
          status: "available",
        },
      }),

      // Paris properties
      prisma.property.upsert({
        where: {
          agencyId_reference: { agencyId: agency2.id, reference: "PAR-001" },
        },
        update: {},
        create: {
          agencyId: agency2.id,
          assignedAgentId: agent2.id,
          reference: "PAR-001",
          title: "T2 Paris 15e - Métro",
          transactionType: "rent",
          propertyType: "apartment",
          cityId: cities[4].id, // Paris
          address: "321 Rue de la Convention",
          postalCode: "75015",
          price: parseFloat("1400"),
          surface: 50,
          rooms: 2,
          bedrooms: 1,
          bathrooms: 1,
          floor: 5,
          hasElevator: true,
          hasBalcony: false,
          isFurnished: false,
          description: "T2 proche métro ligne 6",
          status: "available",
        },
      }),

      prisma.property.upsert({
        where: {
          agencyId_reference: { agencyId: agency2.id, reference: "BOU-001" },
        },
        update: {},
        create: {
          agencyId: agency2.id,
          assignedAgentId: agent2.id,
          reference: "BOU-001",
          title: "Duplex Boulogne - Terrasse",
          transactionType: "rent",
          propertyType: "apartment",
          cityId: cities[5].id, // Boulogne
          address: "654 Avenue Jean-Baptiste Clément",
          postalCode: "92100",
          price: parseFloat("1600"),
          surface: 90,
          rooms: 3,
          bedrooms: 2,
          bathrooms: 2,
          floor: 1,
          hasElevator: false,
          hasBalcony: false,
          hasTerrrace: true,
          hasParking: true,
          isFurnished: false,
          description: "Duplex avec terrasse privée",
          status: "available",
        },
      }),
    ]);

    console.log(`✅ Created ${properties.length} properties\n`);

    // 6. CRÉER DES LEADS
    console.log("📋 Creating leads...");

    const lead1 = await prisma.lead.create({
      data: {
        agencyId: agency1.id,
        assignedAgentId: agent1.id,
        firstName: "Thomas",
        lastName: "Martin",
        email: "thomas.martin@email.com",
        phone: "06 11 22 33 44",
        source: "website",
        transactionType: "rent",
        propertyType: "apartment",
        budgetMin: parseFloat("800"),
        budgetMax: parseFloat("1200"),
        surfaceMin: 50,
        bedroomsMin: 2,
        status: "new",
        priority: "hot",
      },
    });

    // Ajouter les villes
    await prisma.leadCity.createMany({
      data: [
        { leadId: lead1.id, cityId: cities[0].id }, // Marseille
        { leadId: lead1.id, cityId: cities[1].id }, // Aubagne
      ],
    });

    // Ajouter les préférences
    await prisma.leadPreference.createMany({
      data: [
        {
          leadId: lead1.id,
          criteriaKey: "parking",
          value: "true",
          valueType: "boolean",
          importance: "important",
        },
        {
          leadId: lead1.id,
          criteriaKey: "balcony",
          value: "true",
          valueType: "boolean",
          importance: "preferred",
        },
      ],
    });

    const lead2 = await prisma.lead.create({
      data: {
        agencyId: agency2.id,
        firstName: "Sophie",
        lastName: "Bernard",
        email: "sophie.bernard@email.com",
        phone: "06 77 88 99 00",
        source: "seloger",
        transactionType: "rent",
        propertyType: "apartment",
        budgetMin: parseFloat("1200"),
        budgetMax: parseFloat("1800"),
        surfaceMin: 60,
        bedroomsMin: 2,
        status: "new",
        priority: "normal",
      },
    });

    // Ajouter les villes
    await prisma.leadCity.createMany({
      data: [
        { leadId: lead2.id, cityId: cities[4].id }, // Paris
        { leadId: lead2.id, cityId: cities[5].id }, // Boulogne
      ],
    });

    console.log(`✅ Created 2 leads\n`);

    console.log("✨ Seed completed successfully!\n");
    console.log("📊 Summary:");
    console.log(`   - ${cities.length} cities`);
    console.log(`   - 2 agencies`);
    console.log(`   - 3 users`);
    console.log(`   - ${properties.length} properties`);
    console.log(`   - 2 leads\n`);

    console.log("🔑 Test credentials:");
    console.log("   Email: jean.dupont@marseille-immo.fr");
    console.log("   Password: password123\n");
    console.log("   Email: sophie.martin@paris-immo.fr");
    console.log("   Password: password123\n");
  } catch (error) {
    console.error("❌ Error during seed:", error);
    throw error;
  } finally {
    await prisma.$disconnect();
  }
}

main().catch(console.error);
