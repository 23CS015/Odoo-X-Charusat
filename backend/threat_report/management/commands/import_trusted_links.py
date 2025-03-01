import csv
from django.core.management.base import BaseCommand
from threat_report.models import TrustedLink

class Command(BaseCommand):
    help = 'Import trusted links from a CSV file'

    def add_arguments(self, parser):
        parser.add_argument('csv_file', type=str, help='The path to the CSV file')

    def handle(self, *args, **kwargs):
        csv_file = kwargs['csv_file']
        batch_size = 1000  # Adjust the batch size as needed
        links = []

        with open(csv_file, 'r') as file:
            reader = csv.reader(file)
            for row in reader:
                links.append(TrustedLink(url=row[1]))
                if len(links) >= batch_size:
                    TrustedLink.objects.bulk_create(links)
                    links = []

            # Insert any remaining links
            if links:
                TrustedLink.objects.bulk_create(links)

        self.stdout.write(self.style.SUCCESS('Successfully imported trusted links'))