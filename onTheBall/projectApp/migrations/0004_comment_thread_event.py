# Generated by Django 2.2 on 2021-11-15 03:59

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('projectApp', '0003_auto_20211114_2124'),
    ]

    operations = [
        migrations.AddField(
            model_name='comment_thread',
            name='event',
            field=models.ForeignKey(default=1, on_delete=django.db.models.deletion.CASCADE, related_name='event_messages', to='projectApp.Event'),
            preserve_default=False,
        ),
    ]
