const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

async function main() {
  try {
    let city = await prisma.city.findFirst({ where: { inseeCode: '75056' } });
    if (!city) {
      city = await prisma.city.create({
        data: { name: 'Paris', postalCode: '75001', departmentCode: '75', inseeCode: '75056' }
      });
    }

    let agency = await prisma.agency.findFirst({ where: { email: 'contact@paris-immo.fr' } });
    if (!agency) {
      agency = await prisma.agency.create({
        data: { name: 'Paris Immo', email: 'contact@paris-immo.fr', city: { connect: { id: city.id } } }
      });
    }

    await prisma.lead.createMany({
      data: [
        { firstName: 'Thomas', lastName: 'Martin', email: 'thomas.martin@email.com', phone: '0612121212', agencyId: agency.id, transactionType: 'rent', propertyType: 'apartment', status: 'active', budgetMax: 1200, source: 'manual' },
        { firstName: 'Sophie', lastName: 'Dupont', email: 'sophie.dupont@email.com', phone: '0623232323', agencyId: agency.id, transactionType: 'rent', propertyType: 'apartment', status: 'active', budgetMax: 1500, source: 'manual' },
        { firstName: 'Jean', lastName: 'Michel', email: 'jean.michel@email.com', phone: '0634343434', agencyId: agency.id, transactionType: 'sale', propertyType: 'house', status: 'active', budgetMax: 450000, source: 'manual' }
      ]
    });

    await prisma.property.createMany({
      data: [
        { reference: 'PROP-001', title: 'T2 Moderne Marais', description: 'Appartement 2 pièces', propertyType: 'apartment', transactionType: 'rent', status: 'available', address: '42 rue de Turenne', postalCode: '75003', cityId: city.id, price: 1100, surface: 45, bedrooms: 2, agencyId: agency.id },
        { reference: 'PROP-002', title: 'Studio Bastille', description: 'Petit studio', propertyType: 'apartment', transactionType: 'rent', status: 'available', address: '5 boulevard Richard Lenoir', postalCode: '75011', cityId: city.id, price: 850, surface: 20, bedrooms: 1, agencyId: agency.id },
        { reference: 'PROP-003', title: 'Maison Bois de Boulogne', description: 'Belle maison', propertyType: 'house', transactionType: 'sale', status: 'available', address: '123 avenue du Bois', postalCode: '75016', cityId: city.id, price: 550000, surface: 150, bedrooms: 4, agencyId: agency.id }
      ]
    });

    console.log('🎉 TOUT CRÉÉ!');
  } catch(e) { 
    console.error('❌', e.message); 
  }
  process.exit(0);
}

main();
