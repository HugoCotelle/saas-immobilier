const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

async function main() {
  const agency = await prisma.agency.create({
    data: {
      name: 'Paris Immo',
      slug: 'paris-immo',
      email: 'contact@paris-immo.fr'
    }
  });

  const lead = await prisma.lead.create({
    data: {
      firstName: 'Thomas',
      lastName: 'Martin',
      email: 'thomas@test.fr',
      phone: '0612121212',
      agencyId: agency.id,
      transactionType: 'rent',
      propertyType: 'apartment',
      status: 'active',
      budgetMax: 1200,
      source: 'manual'
    }
  });
  console.log('✅ Lead créé:', lead);
  process.exit(0);
}

main().catch(e => { console.error(e); process.exit(1); });
